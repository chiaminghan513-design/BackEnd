# Loyalty shared backend

This server is the single gateway for the member mobile app, member web app, merchant POS, and admin portal. It holds the Xcode Loyalty API authentication details and forwards only approved requests.

## Teammate setup

Requires a maintained Node.js LTS release (Node 22 or newer recommended) and, for the member website, the .NET 8 SDK. This repository contains source and example configuration only. It does not include API credentials, session signing keys, or existing local notification/import records.

```powershell
git clone https://github.com/chiaminghan513-design/BackEnd.git EduvoBackend
cd EduvoBackend
npm ci
Copy-Item .env.example .env
```

Edit `.env` locally before starting:

- Replace `APP_JWT_SECRET` with your own long random signing key. A key generated with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` is suitable for local setup. Never publish that value.
- Set `XCODE_AUTH_PAYLOAD` to the exact authentication JSON supplied privately by the API owner. The example username/password are placeholders and will not log in.
- Keep `PORT=3000` unless you intentionally configure all clients to use a different port.

Then run `npm run dev`. Open `http://localhost:3000/health` to confirm the gateway is running. A successful health response does not by itself prove the provider credentials work; sign into the member website to verify that separately.

### Connect the member website

In a second terminal, navigate to the folder containing `LoyaltyBackend.csproj` in the Group-Assignment-Backend repository:

```powershell
dotnet user-secrets set "SharedGateway:BaseUrl" "http://localhost:3000"
dotnet user-secrets set "SharedGateway:SessionSecret" "PASTE_YOUR_LOCAL_APP_JWT_SECRET_HERE"
dotnet restore
dotnet run
```

The session secret must exactly match `APP_JWT_SECRET` in your local backend `.env`. Restart both applications after configuration changes. User Secrets are private to your Windows account and do not arrive through a Git pull. Do not add secrets to `appsettings.json` or frontend code. Existing development path overrides may reference another developer's `.env`; explicit User Secrets avoid relying on those paths.

`localhost` always means the computer running that process. Running a website on your laptop does not connect it to another teammate's laptop automatically. For independent development, run both the website and this gateway locally. Existing mobile/POS installations may still target the presenter's backend; changing those installations requires their own build/configuration step. All demo clients should use the same gateway instance to share local inbox/import records.

### Verification without real account changes

```powershell
npm test
```

This compiles TypeScript and runs 20 local notification/import checks against temporary synthetic files. It does not call the provider API or modify real members.

### Files that must stay private

`.env`, `data/`, dependency folders, and compiled output are excluded from Git. Obtain the API credentials through a private channel; never paste them into GitHub issues or commits. New clones start with an empty local inbox/import archive. This is the assignment gateway, not a production deployment/security certification.

## Run locally

1. Copy `.env.example` to `.env`.
2. Set `APP_JWT_SECRET` to a long random string.
3. Ask the API owner for the exact `JWTToken/Post` credentials and request body, then set `XCODE_AUTH_PAYLOAD` to that JSON. Do not commit `.env`.
4. Run `npm install`, then `npm run dev`.

The backend starts at `http://localhost:3000`. Check it with `GET /health`.

## Current client routes

- `POST /auth/request-otp`
- `POST /auth/register-otp`
- `POST /auth/login/phone`
- `POST /auth/login/email`
- `POST /auth/register`
- `GET /members/:phoneNumber/dashboard` with `Authorization: Bearer <sessionToken>`

The Xcode authentication request body is intentionally environment-configured because the Swagger page does not document a safe set of test credentials.

Configure `XCODE_AUTH_PAYLOAD` with the real API credentials supplied through Swagger or your lecturer. Accounts, balances, purchases and loyalty actions remain API-backed; no mock OTP or demo-member mode is included.

## Local substitutes for confirmed placeholder APIs

Manual admin/POS messages are persisted in `data/notifications.json` and combined with provider notifications in the mobile/web inbox. Local messages have distinct IDs and per-member read receipts. This is in-app delivery, not phone push. The data directory is resolved from the backend location, so changing the terminal working directory does not lose the inbox. `EDUVO_DATA_DIR` can override it.

Admin CSV imports validate the 13 migration formats and save rows in `data/import-archive.json`. The archive supports history/export and exact-row duplicate detection; credentials are excluded. It does **not** create provider accounts, change live wallets, or add provider transaction records. Do not present it as a live migration to Xcode.

Keep `data/` private and backed up; it is ignored by Git. Only run one backend process against a given data directory. For production, replace the file stores with a database and configure access controls/backups.

The admin's server-to-server client needs `SharedGateway:BaseUrl` and `SharedGateway:SessionSecret` (matching this backend's `APP_JWT_SECRET`), or `SharedGateway:SecretFile` pointing to the backend's private `.env`. Development configuration uses the existing local backend path; configure the secret directly in the deployment environment elsewhere. These credentials never go to the browser. Restart the admin/webpage after their C# changes; the gateway development watcher reloads automatically.
