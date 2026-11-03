# Local account passwords and deployment secrets

## Local Kawal Trace account

- A clean installation shows **Buat akun administrator**. The username, password, and confirmation start empty; the user creates their own credentials.
- The application source and release package must not contain a shared administrator password, sample production token, or live database credential.
- The local account password is validated and stored as a salted PBKDF2 hash in the local identity database. The plain password is not written to a config file, log, source repository, or telemetry.
- Updating an older installation may find an old shared-bootstrap marker or lack the current `local_credentials_setup_v2` marker. In that case, the app asks the user to verify the old local administrator credentials and replace them with private credentials that follow the current bounds. It does not silently delete local users, PINs, audit history, target profiles, or connector settings.
- The app's local login password is not configured through an environment variable. For an interactive Android/desktop app, a baked-in or build-time environment variable is not a safe per-user password source. Environment variables can be inspected by processes with sufficient local privileges and are not a substitute for OS-backed secret storage.

## Environment variables: server/agent runtime only

Environment variables are appropriate for deployment secrets used by a server, CI job, or headless agent, provided the environment is configured by the operator at runtime. For example, a server-side Python process may read a required secret with:

```python
import os

service_password = os.environ.get("DB_PASSWORD")
if not service_password:
    raise RuntimeError("DB_PASSWORD is required for this deployment")
```

This example is for a server/agent process, not the local user's Kawal Trace login form. Never set a sample value as a default, commit a real `.env`/`agent.env`/`api.env`, copy secret files into a release ZIP, or log environment values. The included `*.env.example` files must contain placeholders only. On interactive desktop/mobile use, connector secrets should be entered intentionally and saved via the OS Secure Storage integration where supported.

For larger deployments, an operator may inject the secret from an approved secrets manager during deployment. The app must not require a developer-owned cloud account or make local features depend on a remote secrets service.

## Release checks

Before publishing a release:

1. Search tracked source and documentation for passwords, bearer tokens, private keys, API tokens, and connection strings.
2. Run a secret scanner (for example, Gitleaks or TruffleHog) and review every finding; suppress only verified test fixtures with a narrowly scoped rule.
3. Keep CI secrets in the CI platform's protected secret store and expose them only to jobs that need them.
4. Ensure diagnostic logs redact passwords, API keys, bearer tokens, cookies, and private keys.
5. Test setup/login migration on a clean profile and on an upgraded profile with local data. Do not use tests against a real user's production database.

Environment variables reduce the chance of secrets being committed to a repository, but they are not a magic secret vault. Access controls, least privilege, OS protections, rotation, and careful logging still matter.


## v1.0 local credential limits

New accounts require a username of 4–10 characters (`A–Z`, `a–z`, digits, `.`, `_`, `-`) and a password of 8–128 characters (longer passphrases are encouraged; accounts made under the earlier 6–12 rule still sign in). Use a unique password and keep device/OS protection enabled. Existing accounts without the current `local_credentials_setup_v2` marker are required to rotate credentials after verifying the old password. After that one-time migration, normal login follows the current 4–10 username limit and accepts passwords up to 128 characters.
