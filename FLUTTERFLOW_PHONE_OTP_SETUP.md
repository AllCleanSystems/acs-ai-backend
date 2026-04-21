# FlutterFlow Phone + OTP (Twilio Verify) Setup

This document describes the recommended login flow for the ACS mobile app:

FlutterFlow -> `acs-ai-backend` -> Twilio Verify -> (JWT) -> Zoho Creator.

## Prereqs

1. Twilio Verify Service created (copy the Service SID).
2. `acs-ai-backend` deployed (Railway recommended).
3. Zoho OAuth env vars set on the backend (already used for Creator API calls).

## Backend Environment Variables

Set these on your Railway service (or `.env` locally):

- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_VERIFY_SERVICE_SID`
- `MOBILE_JWT_SECRET` (generate a long random string; do not reuse `FF_API_KEY`)
- `ZOHO_CLIENT_ID`
- `ZOHO_CLIENT_SECRET`
- `ZOHO_REFRESH_TOKEN`
- `ZOHO_CREATOR_OWNER` (example: `allcleansolutions`)
- `ZOHO_CREATOR_APP_LINK` (example: `acs-control-center2`)

Optional:

- `MOBILE_JWT_TTL_SEC` (default 12 hours)
- `ZOHO_CREATOR_TECHNICIANS_REPORT_LINK` (default: `technicians_Report`)
- `ZOHO_CREATOR_WORK_ORDERS_REPORT_LINK` (default: `work_orders_Report`)

## Zoho Creator Data Requirement

For a phone number to be allowed to sign in, it must exist in the **Technicians** form.

Recommended: store technician phone numbers in **E.164** format, like `+17025551234`.

## API Endpoints

### 1) Start OTP

`POST /mobile/auth/start`

Body:

```json
{ "phone": "+17025551234" }
```

Response:

```json
{ "ok": true }
```

### 2) Verify OTP and Get JWT

`POST /mobile/auth/verify`

Body:

```json
{ "phone": "+17025551234", "code": "123456" }
```

Response:

```json
{
  "ok": true,
  "token": "<jwt>",
  "user": { "tech_id": "4879...", "role": "Technician", "phone": "+1...", "name": "Joseph" }
}
```

### 3) Get My Work Orders

`GET /mobile/work-orders?mine=true&open_only=true`

Header:

`Authorization: Bearer <jwt>`

Response:

```json
{ "ok": true, "items": [ ... ] }
```

## FlutterFlow Wiring (High Level)

1. Create a Login page with a phone input and "Send Code" button.
2. On button tap, call `POST /mobile/auth/start`.
3. Navigate to an OTP page with a 6-digit code input.
4. On "Verify", call `POST /mobile/auth/verify`.
5. Store `token` in App State (or Secure Storage).
6. For future API calls, set header: `Authorization: Bearer <token>`.

