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
   - `POST /api/ai/create-intake`
   - `POST /mobile/auth/start`  (Twilio Verify OTP)
   - `POST /mobile/auth/verify` (Twilio Verify OTP -> JWT)

## First Deploy Goal

Deploy this app to Railway first.

After deploy, the public endpoint will be used by:

- Wix frontend chat
- OpenAI tool execution
- later Zoho Creator API calls
- FlutterFlow mobile auth (Phone + OTP) and technician endpoints
