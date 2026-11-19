# idpdemo – SSO test applications for Idira / CyberArk Identity

Two tiny containerised web apps for testing single sign-on against an IdP. Both behave the same way:

1. Open the app → it redirects you to the IdP to authenticate.
2. The IdP sends you back → the app shows everything about the resulting session.
3. A **Log out** button (IdP single logout) and **Local logout only** button are in the header.

| App | Folder | Protocol | Shows |
|---|---|---|---|
| `idp-demo-oidc` | `oidc-app/` | OpenID Connect (auth code + PKCE) | ID/access/refresh tokens (raw + decoded), UserInfo, token expiry countdown, refresh button |
| `idp-demo-saml` | `saml-app/` | SAML 2.0 SP (HTTP-Redirect/POST) | Attributes, NameID, validation results, conditions/SessionNotOnOrAfter, raw assertion + response XML |

Both also show: the app's SSO session cookie (name, flags, timeout, expiry countdown), full app configuration (secrets masked), container/environment details, and request/proxy headers.

## Images

Published by GitHub Actions (`.github/workflows/build-images.yml`) as multi-arch (amd64/arm64):

```
ghcr.io/wvanbesien/idp-demo-oidc:latest
ghcr.io/wvanbesien/idp-demo-saml:latest
```

The workflow runs on pushes to `main`, `v*` tags and manually (Actions → *Build and publish images* → Run workflow). To also push to Docker Hub, set repo variable `DOCKERHUB_NAMESPACE` and secrets `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`. If the GHCR package is private, make it public (Package settings) or `docker login ghcr.io`.

## Run: OIDC

Register an OIDC web-app/client at the IdP with redirect URI `<BASE_URL>/callback` (and post-logout redirect `<BASE_URL>/logged-out`), then:

```bash
docker run --rm -p 8080:8080 \
  -e BASE_URL=http://localhost:8080 \
  -e OIDC_ISSUER=https://<tenant>.id.cyberark.cloud/<app-id>/ \
  -e OIDC_CLIENT_ID=<client id> -e OIDC_CLIENT_SECRET=<secret> \
  ghcr.io/wvanbesien/idp-demo-oidc:latest
```

| Variable | Default | Notes |
|---|---|---|
| `BASE_URL` | `http://localhost:$PORT` | Public URL users reach the app on – must match the registered redirect URI |
| `OIDC_ISSUER` | – (required) | Discovery is read from `<issuer>/.well-known/openid-configuration` (a full discovery URL also works) |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | – | Secret optional (public client + PKCE) |
| `OIDC_CLIENT_AUTH` | `post` (`none` if no secret) | `post`, `basic` or `none` |
| `OIDC_SCOPE` | `openid profile email` | Add `offline_access` for a refresh token |
| `OIDC_PKCE` | `true` | |
| `OIDC_REDIRECT_PATH` | `/callback` | |
| `OIDC_POST_LOGOUT_REDIRECT_URI` | `$BASE_URL/logged-out` | |
| `OIDC_EXTRA_AUTH_PARAMS` | `{}` | JSON, e.g. `{"acr_values":"..."}` |
| `OIDC_ALLOW_INSECURE` | `false` | Allow an `http://` issuer (dev only) |

## Run: SAML

Easiest: give the app the IdP metadata URL, then register the SP at the IdP using `<BASE_URL>/metadata` (SP entity ID `<BASE_URL>/metadata`, ACS `<BASE_URL>/saml/acs` HTTP-POST, SLO `<BASE_URL>/saml/slo`). The app starts without IdP config so you can fetch `/metadata` first.

```bash
docker run --rm -p 8081:8080 \
  -e BASE_URL=http://localhost:8081 \
  -e SAML_IDP_METADATA_URL=https://<tenant>.id.cyberark.cloud/saml/metadata/<app-id> \
  ghcr.io/wvanbesien/idp-demo-saml:latest
```

| Variable | Default | Notes |
|---|---|---|
| `BASE_URL` | `http://localhost:$PORT` | Public URL of the app |
| `SAML_IDP_METADATA_URL` / `SAML_IDP_METADATA_FILE` | – | Provides IdP entity ID, SSO/SLO URLs and signing cert |
| `SAML_IDP_SSO_URL`, `SAML_IDP_CERT` (or `_CERT_FILE`), `SAML_IDP_ENTITY_ID`, `SAML_IDP_SLO_URL` | – | Manual alternative / overrides |
| `SAML_SP_ENTITY_ID` | `$BASE_URL/metadata` | Also the audience unless `SAML_AUDIENCE` is set (`false` disables the check) |
| `SAML_NAMEID_FORMAT` | library default | e.g. `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| `SAML_AUTHN_BINDING` | `redirect` | or `post` |
| `SAML_WANT_ASSERTIONS_SIGNED` / `SAML_WANT_RESPONSE_SIGNED` | `true` / `false` | At least one must be signed |
| `SAML_FORCE_AUTHN` | `false` | |
| `SAML_DISABLE_REQUESTED_AUTHN_CONTEXT` | `true` | |
| `SAML_CLOCK_SKEW_SECONDS` | `60` | |
| `SAML_HONOR_SESSION_NOT_ON_OR_AFTER` | `true` | End the app session when the IdP says so |
| `SAML_SP_PRIVATE_KEY` / `SAML_SP_CERT` (or `_FILE`), `SAML_SIGN_REQUESTS` | – | Needed to decrypt encrypted assertions / sign requests |

## Common settings (both apps)

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `8080` | |
| `SESSION_TIMEOUT_SECONDS` | `3600` | App session cookie lifetime |
| `SESSION_ROLLING` | `true` | `true` = idle timeout, `false` = absolute |
| `SESSION_SECRET` | random per start | Set it to keep sessions across restarts |
| `COOKIE_NAME`, `COOKIE_SAMESITE` (`lax`), `COOKIE_SECURE` | auto from `BASE_URL` | |
| `TRUST_PROXY` | off | Set to `true`/hop count behind a reverse proxy/ingress so `X-Forwarded-*` are honoured |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | – | Serve HTTPS directly from the container (mount the files) |

Notes: sessions are stored in memory (single replica; lost on restart). `GET /healthz` is the health check, `GET /debug.json` dumps the session data. Tokens and assertions are shown in full – use test accounts only.

## Local development

```bash
cd oidc-app   # or saml-app
npm install
BASE_URL=http://localhost:8080 OIDC_ISSUER=... OIDC_CLIENT_ID=... npm start
```

`lib/ui.js` and `lib/boot.js` are identical copies in both apps (each image builds from its own folder) – keep them in sync.
