// Copyright Thales 2026
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { ErrorResponse, UserManager, type User } from "oidc-client-ts";
import type { BrowserSession } from "./BrowserSession";

const REFRESH_TIMEOUT_MS = 8_000;
const TERMINAL_RENEWAL_ERRORS = new Set([
  "invalid_grant",
  "login_required",
  "interaction_required",
  "consent_required",
  "account_selection_required",
]);

export interface GoogleBrowserSessionConfig {
  issuer?: string;
  clientId: string;
  clientSecret?: string;
  apiScope?: string;
  redirectUri: string;
  hostedDomain?: string;
}

/**
 * Dedicated Google Workspace / Google Identity browser session.
 *
 * Why this provider exists:
 * - Google's OAuth 2.0 token endpoint strictly rejects 'offline_access' scope with 400 invalid_scope.
 *   Offline tokens (refresh tokens) are requested exclusively via extra query parameter `access_type=offline`.
 * - For "Web application" client IDs, Google mandates `client_secret` during authorization code exchange
 *   and token refresh, even when PKCE is used.
 * - Google does not support OIDC RP-initiated logout (no end_session_endpoint); session termination
 *   is handled client-side by clearing local user state and returning to the redirect URI.
 */
export class GoogleBrowserSession implements BrowserSession {
  readonly manager: UserManager;
  private user: User | null = null;
  private generation = 0;
  private refreshInFlight: Promise<boolean> | null = null;
  private renewalReconciliation: Promise<void> = Promise.resolve();
  private invalidated = false;
  private readonly redirectUri: string;

  constructor(config: GoogleBrowserSessionConfig) {
    this.redirectUri = config.redirectUri;
    const authority = (config.issuer || "https://accounts.google.com").replace(/\/+$/, "");

    // Google scopes strictly omit 'offline_access' and default to openid, profile, email.
    const scopeTokens = new Set(["openid", "profile", "email"]);
    if (config.apiScope) {
      for (const s of config.apiScope.split(" ")) {
        if (s && s !== "offline_access") scopeTokens.add(s);
      }
    }
    const scope = Array.from(scopeTokens).join(" ");

    const extraQueryParams: Record<string, string> = {
      access_type: "offline",
    };
    if (config.hostedDomain) {
      extraQueryParams.hd = config.hostedDomain;
    }

    this.manager = new UserManager({
      authority,
      client_id: config.clientId,
      client_secret: config.clientSecret || undefined,
      client_authentication: config.clientSecret ? "client_secret_post" : undefined,
      redirect_uri: config.redirectUri,
      silent_redirect_uri: config.redirectUri,
      post_logout_redirect_uri: config.redirectUri,
      response_type: "code",
      scope,
      extraQueryParams,
      disablePKCE: false,
      automaticSilentRenew: false,
      loadUserInfo: false,
      silentRequestTimeoutInSeconds: REFRESH_TIMEOUT_MS / 1000,
    });

    this.manager.events.addAccessTokenExpiring(() => {
      void this.ensureFreshToken(60);
    });
    this.manager.events.addUserUnloaded(() => {
      this.user = null;
    });
  }

  get token(): string | null {
    return this.invalidated || this.user?.expired ? null : (this.user?.id_token ?? this.user?.access_token ?? null);
  }

  get refreshToken(): string | null {
    return this.invalidated ? null : (this.user?.refresh_token ?? null);
  }

  get tokenParsed(): Record<string, unknown> | null {
    const token = this.token;
    if (!token) return null;
    try {
      const payload = token.split(".")[1];
      const bytes = Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0));
      return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  get tokenSecondsLeft(): number | null {
    if (this.invalidated) return 0;
    if (!this.user) return null;
    return this.user.expires_in ?? null;
  }

  async login(onAuthenticated: () => void): Promise<void> {
    const generation = this.generation;
    const query = new URLSearchParams(window.location.search);
    if (query.has("state") && (query.has("code") || query.has("error"))) {
      if (window.self !== window.top) {
        await this.manager.signinSilentCallback();
        return;
      }
      const user = await this.manager.signinRedirectCallback();
      if (generation !== this.generation || this.invalidated) {
        await this.manager.removeUser();
        return;
      }
      this.user = user;
      const requestedPath = user.url_state ?? user.state;
      const returnPath =
        typeof requestedPath === "string" && requestedPath.startsWith("/") && !requestedPath.startsWith("//")
          ? requestedPath
          : this.redirectUri;
      window.history.replaceState({}, "", returnPath);
    } else if (query.has("state")) {
      await this.manager.signoutRedirectCallback();
      window.history.replaceState({}, "", this.redirectUri);
    } else if (query.get("keycloak-login") === "true") {
      query.delete("keycloak-login");
      const search = query.toString();
      const returnPath = `${window.location.pathname}${search ? `?${search}` : ""}${window.location.hash}`;
      window.history.replaceState(window.history.state, "", returnPath);

      const loginGeneration = ++this.generation;
      this.invalidated = true;
      this.user = null;
      await this.reconcileRenewalState();
      if (loginGeneration !== this.generation) return;
      await this.manager.signinRedirect({
        state: returnPath,
        prompt: "select_account consent",
        extraQueryParams: { access_type: "offline" },
      });
      return;
    }

    const restored = this.user ?? (await this.manager.getUser());
    if (generation !== this.generation || this.invalidated) return;
    this.user = restored;
    if (this.user?.expired && this.user.refresh_token) {
      await this.ensureFreshToken(0);
    }
    if ((this.user?.id_token || this.user?.access_token) && !this.user.expired) {
      this.invalidated = false;
      onAuthenticated();
      return;
    }

    const { pathname, search, hash } = window.location;
    await this.manager.signinRedirect({ state: pathname + search + hash });
  }

  async logout(): Promise<void> {
    this.generation += 1;
    this.invalidated = true;
    this.user = null;
    await this.manager.removeUser();
    window.location.assign(this.redirectUri);
  }

  private reconcileRenewalState(): Promise<void> {
    const reconcile = this.renewalReconciliation.then(async () => {
      if (this.invalidated || !this.user) {
        await this.manager.removeUser();
      } else {
        await this.manager.storeUser(this.user);
        await this.manager.getUser();
      }
    });
    this.renewalReconciliation = reconcile.catch(() => undefined);
    return reconcile;
  }

  async ensureFreshToken(minValidity = 30): Promise<boolean> {
    if (this.invalidated || !this.user) return false;
    if (minValidity > 0 && (this.user.expires_in ?? 0) > minValidity) return true;
    if (this.refreshInFlight) {
      const refreshed = await this.refreshInFlight;
      return refreshed && (minValidity <= 0 || (this.user?.expires_in ?? 0) > minValidity);
    }
    const generation = this.generation;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const refresh = Promise.race([
      this.manager.signinSilent().then(async (user) => {
        if (this.invalidated || generation !== this.generation) {
          await this.reconcileRenewalState();
          return null;
        }
        return user;
      }),
      new Promise<null>((resolve) => {
        timeout = setTimeout(() => {
          if (generation === this.generation) this.generation += 1;
          resolve(null);
        }, REFRESH_TIMEOUT_MS);
      }),
    ])
      .then(async (user) => {
        if (!user) return false;
        if (this.invalidated || generation !== this.generation) {
          await this.reconcileRenewalState();
          return false;
        }
        this.user = user;
        await this.reconcileRenewalState();
        if (this.invalidated || generation !== this.generation) {
          await this.reconcileRenewalState();
          return false;
        }
        return true;
      })
      .catch(async (error: unknown) => {
        if (
          generation === this.generation &&
          !this.invalidated &&
          error instanceof ErrorResponse &&
          TERMINAL_RENEWAL_ERRORS.has(error.error ?? "")
        ) {
          this.generation += 1;
          this.invalidated = true;
          this.user = null;
          await this.reconcileRenewalState().catch(() => undefined);
        }
        return false;
      })
      .finally(() => {
        if (timeout) clearTimeout(timeout);
        if (this.refreshInFlight === refresh) this.refreshInFlight = null;
      });
    this.refreshInFlight = refresh;
    const refreshed = await refresh;
    return refreshed && (minValidity <= 0 || (this.user?.expires_in ?? 0) > minValidity);
  }
}
