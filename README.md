# ACS AI Backend

This is the starter backend for:

- Wix website chat
- OpenAI agent orchestration
- Zoho Creator intake creation

## Local Run

1. Install dependencies:
   - `npm install`
2. Start the server:
   - `npm start`
3. Test:
   - `GET /`
   - `GET /health`
   - `POST /mobile/auth/login` (Email + Password -> JWT)
   - `POST /api/ai/create-intake`
   - `POST /mobile/auth/start`  (Twilio Verify OTP)
   - `POST /mobile/auth/verify` (Twilio Verify OTP -> JWT)
   - `POST /mobile/auth/password/bootstrap` (API-key protected password setup)
   - `POST /mobile/auth/password/change` (JWT protected)

## First Deploy Goal

Deploy this app to Railway first.

After deploy, the public endpoint will be used by:

- Wix frontend chat
- OpenAI tool execution
- later Zoho Creator API calls
- FlutterFlow mobile auth (Email/Password or Phone OTP) and technician endpoints
