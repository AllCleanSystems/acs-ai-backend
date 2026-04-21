# FlutterFlow Password Setup (Technicians)

This backend now supports password login without Twilio.

## Endpoints

- `POST /mobile/auth/login` (supports email or phone)
- `POST /mobile/auth/password/bootstrap` (admin/API key required)
- `POST /mobile/auth/password/change` (JWT required)
- `GET /mobile/me` (JWT required)
- `GET /mobile/work-orders` (JWT required)

## 1) Required Zoho Creator fields (Technicians report)

In your `technicians` form/report, confirm these link names exist:

- `email` (or set `ZOHO_CREATOR_TECHNICIAN_EMAIL_FIELD`)
- `mobile_password_hash` (or set `ZOHO_CREATOR_TECHNICIAN_PASSWORD_HASH_FIELD`)
- Optional `auth_provider` (or set `ZOHO_CREATOR_TECHNICIAN_AUTH_PROVIDER_FIELD`)
- Optional active field (set `ZOHO_CREATOR_TECHNICIAN_ACTIVE_FIELD`; leave blank if you do not use one)

## 2) Environment variables

Set these in Railway:

- `MOBILE_JWT_SECRET=<long random string>`
- `MOBILE_JWT_TTL_SEC=86400`
- `MOBILE_LOGIN_MAX_FAILED_ATTEMPTS=5`
- `MOBILE_LOGIN_LOCKOUT_MS=900000`
- `ZOHO_CREATOR_TECHNICIAN_EMAIL_FIELD=email`
- `ZOHO_CREATOR_TECHNICIAN_PASSWORD_HASH_FIELD=mobile_password_hash`
- `ZOHO_CREATOR_TECHNICIAN_ACTIVE_FIELD=`
- `ZOHO_CREATOR_TECHNICIAN_AUTH_PROVIDER_FIELD=auth_provider`
- `FF_API_KEY=<secret>`

## 3) Bootstrap password for a technician

Use API key in header:

```bash
curl -X POST "https://<your-domain>/mobile/auth/password/bootstrap" \
  -H "Content-Type: application/json" \
  -H "x-acs-key: <FF_API_KEY>" \
  -d '{"email":"tech@allclean.com","password":"StrongPass123"}'
```

You can also bootstrap by phone (useful if your technicians form has no email field):

```bash
curl -X POST "https://<your-domain>/mobile/auth/password/bootstrap" \
  -H "Content-Type: application/json" \
  -H "x-acs-key: <FF_API_KEY>" \
  -d '{"phone":"+17015551234","password":"StrongPass123"}'
```

## 4) Login (FlutterFlow)

Request:

Use email:

```json
POST /mobile/auth/login
{
  "email": "tech@allclean.com",
  "password": "StrongPass123"
}
```

Or use phone:

```json
POST /mobile/auth/login
{
  "phone": "+17015551234",
  "password": "StrongPass123"
}
```

Response includes:

- `token`
- `user.tech_id`
- `user.role`
- `user.name`
- `user.email`

Store `token` and send:

- `Authorization: Bearer <token>`

for `/mobile/me` and `/mobile/work-orders`.

## 5) Change password (logged in user)

```json
POST /mobile/auth/password/change
{
  "current_password": "StrongPass123",
  "new_password": "StrongerPass456"
}
```

## Security notes

- Passwords are hashed with `scrypt` before storage.
- Login is protected by in-memory lockout after repeated failures.
- Use HTTPS only (Railway public domain is HTTPS).
