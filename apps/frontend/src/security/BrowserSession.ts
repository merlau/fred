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

import type { UserManager } from "oidc-client-ts";

/** Common contract for browser OIDC sessions behind KeyCloakService facade. */
export interface BrowserSession {
  readonly manager: UserManager;
  readonly token: string | null;
  readonly refreshToken: string | null;
  readonly tokenParsed: Record<string, unknown> | null;
  readonly tokenSecondsLeft: number | null;
  login(onAuthenticated: () => void): Promise<void>;
  logout(): Promise<void>;
  ensureFreshToken(minValidity?: number): Promise<boolean>;
}
