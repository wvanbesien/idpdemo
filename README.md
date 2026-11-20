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

## Deployment with Docker Compose

`docker-compose.yml` runs both apps from the published images and can optionally put a Caddy reverse proxy in front that gets and renews TLS certificates automatically.

### 1. Prerequisites
- A host with Docker and the Compose plugin.
- Two DNS names pointing at the host, one per app (for example `oidc-demo.example.com` and `saml-demo.example.com`).
- The public URL of each app, which becomes its `BASE_URL`. The IdP can only call back to URLs you register, so decide these first.

### 2. Configure
```bash
git clone https://github.com/wvanbesien/idpdemo.git && cd idpdemo
cp .env.example .env
openssl rand -hex 32        # paste the result into SESSION_SECRET in .env
```
Edit `.env`:

| Variable | Meaning |
|---|---|
| `SESSION_SECRET` | Required. Random value so sessions survive restarts |
| `OIDC_BASE_URL`, `SAML_BASE_URL` | Public HTTPS URLs, no port for 443, no trailing slash. These must match what is registered at the IdP |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_SCOPE` | OIDC client settings from the IdP |
| `SAML_IDP_METADATA_URL` | IdP metadata URL (provides SSO/SLO URLs and signing certificate) |
| `OIDC_HOSTNAME`, `SAML_HOSTNAME` | Only for the bundled Caddy proxy: hostnames without `https://` |
| `IMAGE_REGISTRY`, `IMAGE_TAG` | Where to pull from (default `ghcr.io/wvanbesien`, `latest`). Pin a tag for repeatable deployments |

### 3. Register the apps at the IdP
Use the same URLs as in `.env`:

| App | Setting | Value |
|---|---|---|
| OIDC | Redirect URI | `<OIDC_BASE_URL>/callback` |
| OIDC | Post-logout redirect URI | `<OIDC_BASE_URL>/logged-out` |
| SAML | Entity ID | `<SAML_BASE_URL>/metadata` |
| SAML | ACS URL (HTTP-POST) | `<SAML_BASE_URL>/saml/acs` |
| SAML | SLO URL | `<SAML_BASE_URL>/saml/slo` |

For SAML you can instead import `<SAML_BASE_URL>/metadata` once the app is running.

### 4. Start

**Option A: bundled Caddy (automatic HTTPS).** Ports 80 and 443 must be reachable from the internet so Let's Encrypt can validate the hostnames.
```bash
docker compose pull
docker compose --profile caddy up -d
```

**Option B: your own TLS in front** (cloud load balancer, ingress, existing proxy). The apps listen on plain HTTP on host ports `8080` (OIDC) and `8081` (SAML), configurable with `OIDC_HOST_PORT` / `SAML_HOST_PORT`. Terminate TLS on 443 and forward to those ports, passing the standard `X-Forwarded-Proto` and `X-Forwarded-For` headers (`TRUST_PROXY=true` is already set in the compose file).
```bash
docker compose pull
docker compose up -d
```

In both cases the containers are not given port 443 themselves; TLS is handled by the proxy.

### 5. Verify
```bash
docker compose ps                      # both apps should become "healthy"
docker compose logs -f oidc saml
curl -fsS https://<SAML_BASE_URL host>/healthz    # prints: ok
```
Browse to each `BASE_URL`: you should be redirected to the IdP, then land back on the details page. Its *Application configuration* section lists the redirect URI / entity ID / ACS URL the app is really using; compare them with what you registered if the IdP reports a mismatch.

### Operations
```bash
docker compose pull && docker compose up -d     # update to the latest images
docker compose down                             # stop and remove (sessions are in memory and are lost)
docker compose up -d --build                    # build from source instead of pulling
```
- Run a single replica of each app: sessions are kept in memory.
- If `docker compose pull` is denied, the GHCR packages are private: make them public in the package settings or `docker login ghcr.io`.
- Need a custom CA for an internal IdP? Mount the CA file and set `NODE_EXTRA_CA_CERTS` on the app service.
- Other settings from the tables below (for example `SAML_FORCE_AUTHN`, `OIDC_EXTRA_AUTH_PARAMS`) can be added to the service's `environment:` in `docker-compose.yml`.

### Azure Container Apps and other managed platforms
- Set ingress **target port 8080** (or whatever `PORT` is) and let the platform terminate TLS; set `BASE_URL` to the public `https://` FQDN (for Azure: `https://<app>.<env-hash>.<region>.azurecontainerapps.io` or your custom domain).
- Set **min replicas = max replicas = 1**. Sessions are held in memory, so with several replicas (or scale-to-zero) the browser lands on an instance that has no session and login loops. Session affinity helps only partially; one replica is the reliable setting.
- Set a fixed `SESSION_SECRET` (use a secret reference).
- `TRUST_PROXY` is turned on automatically when `BASE_URL` is `https://` and the container is not serving TLS itself. If you set it explicitly to `false` behind an HTTPS proxy, no session cookie is stored and login loops forever (the log prints a warning).
- Redirect loop checklist: `docker logs` / Log stream should show `trust proxy: true`; `/healthz` works; only one replica is running; `BASE_URL` matches the URL in the browser exactly.

### Common problems
| Symptom | Likely cause |
|---|---|
| IdP says redirect URI / ACS mismatch | `BASE_URL` differs from what is registered (scheme, host, trailing slash) |
| Login loops back to the login page or "No login in progress" (more than one replica, or Secure cookie not stored) | Proxy not sending `X-Forwarded-Proto: https`, or `BASE_URL` is `http://` while users browse over HTTPS (cookie is not stored) |
| Everyone logged out after restart | `SESSION_SECRET` not set to a fixed value |
| SAML "audience" or "recipient" error | Entity ID / ACS at the IdP does not match `SAML_BASE_URL` |
| SAML "invalid signature" | Usually the IdP signs with a different certificate than the one in its metadata, or only the Response (not the Assertion) is signed. The error page and `docker compose logs saml` now state which: they list the certificate fingerprint found in the response vs the configured one, which elements are signed, and the likely fix. The app reads the IdP metadata at startup, so restart after rotating certificates |
| Caddy cannot get certificates | DNS does not point at the host yet, or ports 80/443 are blocked |

## Run a single container: OIDC

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

## Run a single container: SAML


**Which metadata goes where:** `SAML_IDP_METADATA_URL` is one-way: the app *reads* the IdP's metadata (SSO/SLO URLs, signing certificate). It tells the IdP nothing. The IdP needs the app's own metadata, served at `<BASE_URL>/metadata`: import that URL (or download the XML and upload it) in the IdP's SAML application settings, or enter the entity ID, ACS and SLO URLs by hand. The IdP must be able to reach the URL if you import by URL; otherwise upload the file.

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
| `SAML_WANT_ASSERTIONS_SIGNED` / `SAML_WANT_RESPONSE_SIGNED` | `false` / `false` | By default either the Response or the Assertion may be signed (at least one valid signature is always required). Set one to `true` to insist on that element |
| `SAML_FORCE_AUTHN` | `false` | |
| `SAML_DISABLE_REQUESTED_AUTHN_CONTEXT` | `true` | |
| `SAML_CLOCK_SKEW_SECONDS` | `60` | |
| `SAML_HONOR_SESSION_NOT_ON_OR_AFTER` | `true` | End the app session when the IdP says so |
| `SAML_DEBUG` | `false` | Also log the full raw SAMLResponse XML on rejection (contains user data – use for troubleshooting only) |
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
