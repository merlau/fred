---
schema: 1
title: "Add dedicated GoogleBrowserSession OIDC provider for Google Workspace SSO"
impact: none
configuration: none
configuration_reason: "Frontend auto-detects accounts.google.com realm URLs or explicit user_auth_provider=google; existing Keycloak and generic OIDC configurations and defaults are unchanged."
no_action_reason: "Existing deployments using Keycloak or generic OIDC upgrade normally with no configuration, secret, or data changes required."
---
## Applicability

Existing Fred deployments upgrading to this release, and operators configuring Google Workspace OIDC (`https://accounts.google.com`) as the user authentication provider.

## Prerequisites

No additional prerequisites beyond the normal deployment procedure for existing Keycloak or generic OIDC deployments. Operators using Google Workspace OAuth 2.0 Web Application clients may optionally provide `GOOGLE_CLIENT_SECRET` in the frontend container environment.

## Configuration

No configuration changes are required for existing deployments. When `security.user.realm_url` targets `https://accounts.google.com`, the frontend automatically selects `GoogleBrowserSession` and reads `/google-auth.json` if `GOOGLE_CLIENT_SECRET` is set on the frontend container.

## Upgrade

Deploy Fred normally; no additional operator or user action is required.

## Validation

Sign in through the frontend using the configured OIDC provider (or run `npx vitest run src/security/GoogleBrowserSession.test.ts src/security/KeycloakService.oidc.test.ts`) and verify that `/control-plane/v1/frontend/bootstrap` succeeds with `200 OK`.

## Rollback

Use the normal rollback procedure; this change introduces no data migration.

## Limitations

No additional migration limitations identified for this change.
