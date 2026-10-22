// @vitest-environment happy-dom
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

import { User } from "oidc-client-ts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GoogleBrowserSession } from "./GoogleBrowserSession";

const sessions: GoogleBrowserSession[] = [];

function googleUser(seconds = 300, subject = "108342738947239847293"): User {
  const now = Math.floor(Date.now() / 1000);
  const profile = {
    iss: "https://accounts.google.com",
    aud: "google-client-id",
    sub: subject,
    email: "user@nemos.s3ns.cloud",
    email_verified: true,
    name: "Test User",
    iat: now,
    exp: now + seconds,
  };
  const payload = btoa(JSON.stringify(profile)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return new User({
    id_token: `header.${payload}.signature`,
    access_token: "ya29.a0AfB_byC-opaque-google-access-token",
    refresh_token: "google-refresh-token",
    token_type: "Bearer",
    expires_at: now + seconds,
    profile,
  });
}

function newGoogleSession(clientSecret = "test-secret"): GoogleBrowserSession {
  const session = new GoogleBrowserSession({
    issuer: "https://accounts.google.com",
    clientId: "google-client-id",
    clientSecret,
    redirectUri: window.location.origin + "/",
  });
  sessions.push(session);
  return session;
}

beforeEach(() => {
  window.history.replaceState({}, "", "/");
  window.sessionStorage.clear();
});

afterEach(async () => {
  vi.restoreAllMocks();
  for (const session of sessions.splice(0)) await session.manager.removeUser();
  window.sessionStorage.clear();
  window.history.replaceState({}, "", "/");
});

describe("GoogleBrowserSession", () => {
  it("configures client_secret_post and omits offline_access scope", () => {
    const session = newGoogleSession("secret-123");
    expect(session.manager.settings.client_secret).toBe("secret-123");
    expect(session.manager.settings.client_authentication).toBe("client_secret_post");
    expect(session.manager.settings.scope).toBe("openid profile email");
    expect(session.manager.settings.scope).not.toContain("offline_access");
    expect(session.manager.settings.extraQueryParams).toEqual({
      access_type: "offline",
    });
  });

  it("handles login callback and restores Google user", async () => {
    const session = newGoogleSession();
    const gUser = googleUser();
    vi.spyOn(session.manager, "signinRedirectCallback").mockResolvedValue(gUser);
    window.history.replaceState({}, "", "/?code=dummy-google-code&state=dummy-state");

    const authenticated = vi.fn();
    await session.login(authenticated);

    expect(authenticated).toHaveBeenCalledOnce();
    expect(session.token).toBe(gUser.id_token);
    expect(session.refreshToken).toBe("google-refresh-token");
    expect(session.tokenParsed?.email).toBe("user@nemos.s3ns.cloud");
  });

  it("clears user session on logout without provider redirect error", async () => {
    const session = newGoogleSession();
    const gUser = googleUser();
    await session.manager.storeUser(gUser);

    const removeSpy = vi.spyOn(session.manager, "removeUser");
    const assignSpy = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign: assignSpy });

    await session.logout();

    expect(removeSpy).toHaveBeenCalledOnce();
    expect(session.token).toBeNull();
    expect(session.refreshToken).toBeNull();
  });
});
