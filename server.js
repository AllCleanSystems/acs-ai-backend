const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const fetch = require("node-fetch");
const OpenAI = require("openai");
const twilio = require("twilio");
const crypto = require("crypto");

dotenv.config();

const app = express();
// Needed so req.protocol reflects X-Forwarded-Proto on Railway.
app.set("trust proxy", true);
const port = process.env.PORT || 3001;
const REQUEST_TIMEOUT_MS = 15000;
const RETRY_DELAY_MS = 1200;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";

app.use(cors());
// Twilio sends webhooks as application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

// Outbound Twilio SMS (for internal alerts). Requires:
// - TWILIO_ACCOUNT_SID
// - TWILIO_AUTH_TOKEN
// - TWILIO_FROM_NUMBER (your Twilio number, e.g. +1701...)
const twilioClient =
  process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN
    ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
    : null;

// ----------------------------
// Mobile auth (Phone + OTP)
// ----------------------------
// Uses Twilio Verify to send/check OTP codes.
// FlutterFlow flow:
// 1) POST /mobile/auth/start  { phone }
// 2) POST /mobile/auth/verify { phone, code }  -> returns JWT
//
// Notes:
// - Phone numbers must be E.164 for Twilio Verify (example: +17025551234).
// - For simplicity (US-first), we auto-normalize 10-digit numbers to +1xxxxxxxxxx.
function normalizePhoneToE164(input) {
  const raw = (input || "").toString().trim();
  if (!raw) {
    throw new Error("phone is required.");
  }
  if (raw.startsWith("+")) {
    const cleaned = raw.replace(/[^\d+]/g, "");
    if (!/^\+[0-9]{8,15}$/.test(cleaned)) {
      throw new Error("phone must be in E.164 format (example: +17025551234).");
    }
    return cleaned;
  }
  const digits = raw.replace(/\D/g, "");
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  throw new Error("phone must be in E.164 format (example: +17025551234).");
}

function base64urlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64urlEncodeJson(obj) {
  return base64urlEncode(JSON.stringify(obj));
}

function base64urlDecodeToString(b64url) {
  const padded = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function signJwtHs256(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const headerPart = base64urlEncodeJson(header);
  const payloadPart = base64urlEncodeJson(payload);
  const data = `${headerPart}.${payloadPart}`;
  const sig = crypto.createHmac("sha256", secret).update(data).digest("base64");
  const sigUrl = sig.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${data}.${sigUrl}`;
}

function verifyJwtHs256(token, secret) {
  const t = (token || "").toString().trim();
  const parts = t.split(".");
  if (parts.length !== 3) {
    const err = new Error("Invalid token.");
    err.statusCode = 401;
    throw err;
  }
  const [headerPart, payloadPart, sigPart] = parts;
  const data = `${headerPart}.${payloadPart}`;
  const expected = crypto.createHmac("sha256", secret).update(data).digest("base64");
  const expectedUrl = expected.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const a = Buffer.from(expectedUrl);
  const b = Buffer.from(sigPart);
  // timingSafeEqual throws if lengths differ.
  if (a.length !== b.length) {
    const err = new Error("Invalid token.");
    err.statusCode = 401;
    throw err;
  }
  const ok = crypto.timingSafeEqual(a, b);
  if (!ok) {
    const err = new Error("Invalid token.");
    err.statusCode = 401;
    throw err;
  }
  const payloadText = base64urlDecodeToString(payloadPart);
  let payload;
  try {
    payload = JSON.parse(payloadText);
  } catch {
    const err = new Error("Invalid token payload.");
    err.statusCode = 401;
    throw err;
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (payload && typeof payload.exp === "number" && nowSec >= payload.exp) {
    const err = new Error("Token expired.");
    err.statusCode = 401;
    throw err;
  }
  return payload;
}

function issueMobileJwt({ techId, phoneE164, role, displayName }) {
  const secret = (process.env.MOBILE_JWT_SECRET || "").toString().trim();
  if (!secret) {
    const err = new Error("Server missing MOBILE_JWT_SECRET.");
    err.statusCode = 500;
    throw err;
  }
  const ttlSec = Number(process.env.MOBILE_JWT_TTL_SEC || 60 * 60 * 12); // default 12h
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    sub: String(techId),
    phone: phoneE164,
    role: role || "Technician",
    name: displayName || "",
    iat: nowSec,
    exp: nowSec + Math.max(60, ttlSec)
  };
  return signJwtHs256(payload, secret);
}

function requireMobileJwt(req, res, next) {
  try {
    const header = (req.get("authorization") || "").toString();
    const token = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : "";
    if (!token) {
      return res.status(401).json({ ok: false, error: "Missing Authorization: Bearer <token>." });
    }
    const secret = (process.env.MOBILE_JWT_SECRET || "").toString().trim();
    if (!secret) {
      return res.status(500).json({ ok: false, error: "Server missing MOBILE_JWT_SECRET." });
    }
    const payload = verifyJwtHs256(token, secret);
    req.mobileUser = payload;
    return next();
  } catch (err) {
    const status = err.statusCode || 401;
    return res.status(status).json({ ok: false, error: err.message || "Unauthorized." });
  }
}

// In-memory SMS sessions (best-effort). If Railway restarts, sessions reset.
// Keyed by "sms_<FromPhoneNumber>".
const smsSessions = new Map();
const SMS_SESSION_TTL_MS = 1000 * 60 * 60 * 6; // 6 hours

function getSmsSession(sessionId) {
  const now = Date.now();
  const existing = smsSessions.get(sessionId);
  if (existing && now - existing.lastSeen < SMS_SESSION_TTL_MS) {
    existing.lastSeen = now;
    return existing;
  }
  const fresh = { lastSeen: now, history: [], intakeCreated: false, emergencyAlertSent: false };
  smsSessions.set(sessionId, fresh);
  return fresh;
}

function cleanupSmsSessions() {
  const now = Date.now();
  for (const [key, value] of smsSessions.entries()) {
    if (!value || now - (value.lastSeen || 0) > SMS_SESSION_TTL_MS) {
      smsSessions.delete(key);
    }
  }
}
setInterval(cleanupSmsSessions, 1000 * 60 * 30).unref();

const SERVICE_TYPE_MAP = {
  "restaurant hood cleaning": "Hood Cleaning",
  "carpet cleaning": "Carpet Cleaning",
  "carpet clean": "Carpet Cleaning",
  "window cleaning": "Window Cleaning",
  "commercial cleaning": "Commercial Cleaning",
  "lawn maintenance": "Lawn Maintenance",
  "lawn maintenace": "Lawn Maintenance",
  "snow removal": "Snow Removal",
  "food truck cleaning": "Food Truck Cleaning",
  "hood cleaning": "Hood Cleaning",
  other: "Other"
};

const URGENCY_MAP = {
  emergency: "Emergency",
  high: "High",
  normal: "Normal",
  low: "Low"
};

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableStatus(status) {
  return status === 408 || status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}

function isRetryableNetworkError(error) {
  const code = error && error.code ? String(error.code) : "";
  const message = error && error.message ? String(error.message).toLowerCase() : "";
  return code === "ETIMEDOUT" || code === "ECONNRESET" || code === "EAI_AGAIN" || message.includes("timeout") || message.includes("network");
}

function normalizeText(value) {
  if (!value) {
    return "";
  }
  return String(value).trim().toLowerCase();
}

function mapServiceType(value) {
  const key = normalizeText(value);
  return SERVICE_TYPE_MAP[key] || "Other";
}

function mapUrgency(value) {
  const key = normalizeText(value);
  return URGENCY_MAP[key] || "Normal";
}

async function sendAdminAlertSms(text) {
  const to = (process.env.ADMIN_ALERT_PHONE || "").toString().trim();
  const from = (process.env.TWILIO_FROM_NUMBER || "").toString().trim();

  if (!to || !from || !twilioClient) {
    console.warn("admin-alert not sent (missing TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/TWILIO_FROM_NUMBER/ADMIN_ALERT_PHONE)");
    return;
  }

  try {
    await twilioClient.messages.create({
      to,
      from,
      body: String(text || "").slice(0, 1500)
    });
  } catch (err) {
    console.error("admin-alert send failed:", err && err.message ? err.message : err);
  }
}

function buildSystemPrompt() {
  return [
    "You are the ACS website intake assistant.",
    "Collect intake details for a service request.",
    "Required before creating intake:",
    "- customer_name",
    "- service_type",
    "- urgency",
    "- request_summary",
    "- at least one contact: phone or email",
    "Rules:",
    "- Keep responses concise and friendly.",
    "- Ask short follow-up questions only when needed.",
    "- Do not promise pricing or appointment times.",
    "- When ready, call create_ai_intake."
  ].join("\n");
}

function buildPhoneSystemPrompt() {
  return [
    "You are ACS's live phone receptionist. Sound warm, calm, and human.",
    "Goal: collect details for a service intake and submit it.",
    "Required before creating intake:",
    "- customer_name",
    "- service_type",
    "- urgency",
    "- request_summary",
    "- at least one contact: phone or email",
    "Style rules:",
    "- Ask one question at a time.",
    "- Use short sentences and friendly confirmations.",
    "- Acknowledge stress before asking the next question.",
    "- Do not promise pricing or appointment times.",
    "When required fields are present, call create_ai_intake."
  ].join("\n");
}

function normalizeChannel(value) {
  const v = normalizeText(value);
  if (v === "phone") return "Phone";
  return "Website Chat";
}

function createIntakeToolSchema() {
  return {
    type: "function",
    name: "create_ai_intake",
    description: "Create an AI intake record in Zoho Creator.",
    parameters: {
      type: "object",
      properties: {
        channel: { type: "string", enum: ["Website Chat", "Phone"] },
        customer_name: { type: "string" },
        phone: { type: "string" },
        email: { type: "string" },
        address: { type: "string" },
        service_type: { type: "string" },
        urgency: { type: "string", enum: ["Emergency", "High", "Normal", "Low"] },
        request_summary: { type: "string" },
        intent: { type: "string" },
        chat_session_id: { type: "string" }
      },
      required: ["channel", "customer_name", "service_type", "urgency", "request_summary"]
    }
  };
}

function extractFunctionCall(response) {
  if (!response || !Array.isArray(response.output)) {
    return null;
  }
  for (const item of response.output) {
    if (item.type === "function_call" && item.name === "create_ai_intake") {
      return item;
    }
  }
  return null;
}

function responseText(response) {
  if (response && typeof response.output_text === "string" && response.output_text.trim() !== "") {
    return response.output_text;
  }
  return "Thanks. I can help with that. Can you share your name and best contact info?";
}

function escapeXml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function buildTranscriptFromHistory(history, maxLines = 14) {
  const lines = [];
  const slice = history.slice(Math.max(0, history.length - maxLines));
  for (const msg of slice) {
    const role = msg.role === "assistant" ? "ACS AI" : "Customer";
    lines.push(`${role}: ${String(msg.content || "").trim()}`);
  }
  return lines.join("\n");
}

// ----------------------------
// FlutterFlow wrapper API auth
// ----------------------------
// FlutterFlow sends: x-acs-key: <FF_API_KEY>
function requireFlutterFlowApiKey(req, res, next) {
  const required = (process.env.FF_API_KEY || "").toString().trim();
  if (!required) {
    return res.status(500).json({ ok: false, error: "Server missing FF_API_KEY." });
  }
  const provided = (req.get("x-acs-key") || req.get("authorization") || "").toString().trim();
  const token = provided.toLowerCase().startsWith("bearer ") ? provided.slice(7).trim() : provided;
  if (!token || token !== required) {
    return res.status(401).json({ ok: false, error: "Unauthorized." });
  }
  next();
}

function creatorBaseUrl() {
  return (process.env.ZOHO_CREATOR_BASE_URL || "https://www.zohoapis.com").replace(/\/+$/, "");
}

function creatorOwnerAndApp() {
  const owner = (process.env.ZOHO_CREATOR_OWNER || "").toString().trim();
  let appLink = (process.env.ZOHO_CREATOR_APP_LINK || "").toString().trim();
  if (!owner || !appLink) {
    throw new Error("Missing ZOHO_CREATOR_OWNER or ZOHO_CREATOR_APP_LINK.");
  }

  // Accept either the app link name (recommended) or a full Creator URL.
  // Example URL: https://creatorapp.zoho.com/allcleansolutions/acs-control-center2
  if (appLink.includes("/") || appLink.toLowerCase().startsWith("http")) {
    try {
      const asUrl = new URL(appLink);
      const parts = asUrl.pathname.split("/").filter(Boolean);
      const ownerIdx = parts.findIndex((p) => p.toLowerCase() === owner.toLowerCase());
      if (ownerIdx >= 0 && ownerIdx + 1 < parts.length) {
        appLink = parts[ownerIdx + 1];
      } else if (parts.length > 0) {
        appLink = parts[parts.length - 1];
      }
    } catch {
      const parts = appLink.split("/").filter(Boolean);
      if (parts.length > 0) appLink = parts[parts.length - 1];
    }
  }
  return { owner, appLink };
}

async function creatorGetReport(reportLink, query = {}) {
  const accessToken = await getZohoAccessToken();
  const { owner, appLink } = creatorOwnerAndApp();

  const url = new URL(`${creatorBaseUrl()}/creator/v2.1/data/${owner}/${appLink}/report/${reportLink}`);

  // Pass-through supported query params (all optional)
  const allowed = [
    "criteria",
    "page",
    "per_page",
    "max_records",
    "sort_by",
    "sort_order",
    "field_config"
  ];
  for (const key of allowed) {
    if (query[key] !== undefined && query[key] !== null && String(query[key]).trim() !== "") {
      url.searchParams.set(key, String(query[key]));
    }
  }

  const response = await fetchWithRetry(
    url.toString(),
    { method: "GET", headers: { Authorization: `Zoho-oauthtoken ${accessToken}` } },
    "zoho-creator-report"
  );
  const data = await safeJson(response);
  if (!response.ok) {
    throw new Error(`Zoho Creator report GET error: ${JSON.stringify(data)}`);
  }
  return data;
}

async function creatorGetRecord(reportLink, recordId) {
  const accessToken = await getZohoAccessToken();
  const { owner, appLink } = creatorOwnerAndApp();
  const url = new URL(
    `${creatorBaseUrl()}/creator/v2.1/data/${encodeURIComponent(owner)}/${encodeURIComponent(appLink)}/report/${encodeURIComponent(
      reportLink
    )}/${encodeURIComponent(String(recordId))}`
  );

  const response = await fetchWithRetry(
    url.toString(),
    { method: "GET", headers: { Authorization: `Zoho-oauthtoken ${accessToken}` } },
    "zoho-creator-record-get"
  );
  const data = await safeJson(response);
  if (!response.ok) {
    throw new Error(`Zoho Creator record GET error: ${JSON.stringify(data)}`);
  }
  return data;
}

async function creatorUpdateRecord(reportLink, recordId, updateData) {
  const accessToken = await getZohoAccessToken();
  const { owner, appLink } = creatorOwnerAndApp();
  const url = new URL(
    `${creatorBaseUrl()}/creator/v2.1/data/${encodeURIComponent(owner)}/${encodeURIComponent(appLink)}/report/${encodeURIComponent(
      reportLink
    )}/${encodeURIComponent(String(recordId))}`
  );

  const body = { data: updateData };
  const response = await fetchWithRetry(
    url.toString(),
    {
      method: "PATCH",
      headers: {
        Authorization: `Zoho-oauthtoken ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    },
    "zoho-creator-record-patch"
  );
  const data = await safeJson(response);
  if (!response.ok) {
    throw new Error(`Zoho Creator record PATCH error: ${JSON.stringify(data)}`);
  }
  return data;
}

function shouldValidateTwilioRequests() {
  // If auth token isn't configured, skip validation (dev-friendly).
  // If it is configured, validate by default.
  const token = process.env.TWILIO_AUTH_TOKEN;
  if (!token) return false;
  const flag = (process.env.TWILIO_VALIDATE_REQUESTS || "").toString().trim().toLowerCase();
  if (flag === "false" || flag === "0" || flag === "no") return false;
  return true;
}

function validateTwilioRequestOrThrow(req) {
  if (!shouldValidateTwilioRequests()) return;

  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const signature = (req.get("X-Twilio-Signature") || "").toString();

  // Twilio validates against the exact URL you configured in the console.
  const url = `${req.protocol}://${req.get("host")}${req.originalUrl}`;

  const ok = twilio.validateRequest(authToken, signature, url, req.body || {});
  if (!ok) {
    const err = new Error("Invalid Twilio signature");
    err.status = 403;
    throw err;
  }
}

async function safeJson(response) {
  const text = await response.text();
  if (!text) {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    return { raw: text };
  }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchWithRetry(url, options = {}, context = "request") {
  let lastError;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      const response = await fetchWithTimeout(url, options, REQUEST_TIMEOUT_MS);
      if (attempt === 1 && isRetryableStatus(response.status)) {
        console.warn(`${context} retrying due to HTTP ${response.status}`);
        await delay(RETRY_DELAY_MS);
        continue;
      }
      return response;
    } catch (error) {
      lastError = error;
      if (attempt === 1 && isRetryableNetworkError(error)) {
        console.warn(`${context} retrying after network error: ${error.message}`);
        await delay(RETRY_DELAY_MS);
        continue;
      }
      throw error;
    }
  }
  throw lastError || new Error(`${context} failed`);
}

// Zoho OAuth token caching (in-memory).
// Zoho access tokens are short-lived. Refresh tokens must be kept server-side.
// Without caching, UI polling/tests can cause repeated refresh_token calls and trigger Zoho throttling.
let zohoAccessTokenCache = "";
let zohoAccessTokenExpiresAtMs = 0;
let zohoTokenRefreshInFlight = null;
let zohoTokenCooldownUntilMs = 0;

async function getZohoAccessToken() {
  const now = Date.now();

  // If we have a token that is still valid for at least 30 seconds, reuse it.
  if (zohoAccessTokenCache && now + 30_000 < zohoAccessTokenExpiresAtMs) {
    return zohoAccessTokenCache;
  }

  // If Zoho is throttling refresh calls, avoid hammering their token endpoint.
  if (now < zohoTokenCooldownUntilMs && !(zohoAccessTokenCache && now < zohoAccessTokenExpiresAtMs)) {
    throw new Error("Zoho token error: throttled. Please wait a minute and try again.");
  }

  // Coalesce concurrent refreshes into one request.
  if (zohoTokenRefreshInFlight) {
    return zohoTokenRefreshInFlight;
  }

  zohoTokenRefreshInFlight = (async () => {
  const params = new URLSearchParams({
    refresh_token: process.env.ZOHO_REFRESH_TOKEN || "",
    client_id: process.env.ZOHO_CLIENT_ID || "",
    client_secret: process.env.ZOHO_CLIENT_SECRET || "",
    grant_type: "refresh_token"
  });

  const tokenUrl = "https://accounts.zoho.com/oauth/v2/token";
  const response = await fetchWithRetry(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: params.toString()
  }, "zoho-token");

  const data = await safeJson(response);

  if (!response.ok || !data.access_token) {
    const desc = (data && (data.error_description || data.error)) ? String(data.error_description || data.error) : "";
    // Zoho sometimes returns "You have made too many requests continuously. Please try again after some time."
    // Put the refresh path on cooldown to prevent immediate retry storms.
    if (desc.toLowerCase().includes("too many requests continuously")) {
      zohoTokenCooldownUntilMs = Date.now() + 60_000;
    }
    throw new Error(`Zoho token error: ${JSON.stringify(data)}`);
  }

  const token = String(data.access_token);
  // Prefer expires_in_sec if present; otherwise assume ~1 hour.
  const expiresInSec = Number(data.expires_in_sec || data.expires_in || 3600);
  const ttlMs = Math.max(60_000, (expiresInSec - 60) * 1000); // refresh 60s early, min 60s ttl

  zohoAccessTokenCache = token;
  zohoAccessTokenExpiresAtMs = Date.now() + ttlMs;
  return token;
  })().finally(() => {
    zohoTokenRefreshInFlight = null;
  });

  return zohoTokenRefreshInFlight;
}

async function createZohoAiIntakeRecord(payload) {
  const accessToken = await getZohoAccessToken();

  const owner = process.env.ZOHO_CREATOR_OWNER;
  const appLink = process.env.ZOHO_CREATOR_APP_LINK;
  // Creator "form link name" (not display name). New app uses `ai_intake_log`.
  // Keep env override so you can switch apps without code changes.
  const formLink = process.env.ZOHO_CREATOR_AI_INTAKE_FORM_LINK || "ai_intake_log";

  const creatorBase = (process.env.ZOHO_CREATOR_BASE_URL || "https://www.zohoapis.com").replace(/\/+$/, "");
  const url = `${creatorBase}/creator/v2.1/data/${owner}/${appLink}/form/${formLink}`;

  // New ACS app (from your .ds export) uses lowercase link names (ai_intake_log form):
  // channel, customer_name, phone, email, address_text, service_type, urgency,
  // preferred_window, request_summary, transcript, chat_session_id, ai_confidence, status, ...
  const dataPayloadV2 = {
    channel: payload.channel,
    customer_name: payload.customer_name,
    phone: payload.phone || "",
    email: payload.email || "",
    address_text: payload.address || "",
    service_type: payload.service_type,
    urgency: payload.urgency,
    preferred_window: payload.preferred_window || "",
    request_summary: payload.request_summary,
    transcript: payload.transcript || "",
    chat_session_id: payload.chat_session_id || "",
    ai_confidence:
      payload.ai_confidence === null || payload.ai_confidence === undefined || payload.ai_confidence === ""
        ? null
        : Number(payload.ai_confidence),
    status: "New",
    // Let Creator workflows set timestamps; sending date-times in the wrong format causes 3001 errors.
    last_sync_source: "Railway"
  };

  // Legacy fallback payload (older app variants that used Title Case link names + Address object)
  const dataPayloadLegacy = {
    Channel: payload.channel,
    Customer_Name: payload.customer_name,
    Phone: payload.phone || "",
    Email: payload.email || "",
    Service_Type: payload.service_type,
    Urgency: payload.urgency,
    Preferred_Window: payload.preferred_window || "",
    Request_Summary: payload.request_summary,
    Transcript: payload.transcript || "",
    Intent: payload.intent || "",
    Chat_Session_ID: payload.chat_session_id || "",
    AI_Confidence:
      payload.ai_confidence === null || payload.ai_confidence === undefined || payload.ai_confidence === ""
        ? null
        : Number(payload.ai_confidence),
    Status: "New",
    Last_Sync_Source: "Railway"
  };

  const candidateBodies = [
    { data: dataPayloadV2 },
    { data: dataPayloadLegacy }
  ];

  let lastErr = null;
  for (const body of candidateBodies) {
    try {
      const response = await fetchWithRetry(
        url,
        {
          method: "POST",
          headers: {
            Authorization: `Zoho-oauthtoken ${accessToken}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(body)
        },
        "zoho-creator-create"
      );

      const data = await safeJson(response);

      if (!response.ok || (data && data.code && data.code !== 3000)) {
        lastErr = new Error(`Zoho Creator create record error: ${JSON.stringify(data)}`);
        continue;
      }

      return data;
    } catch (err) {
      lastErr = err;
    }
  }

  throw lastErr || new Error("Zoho Creator create record failed.");
}

function escapeCreatorCriteriaString(value) {
  // Creator criteria strings are wrapped in double-quotes.
  // Escape backslashes and quotes so we can safely embed values.
  return String(value || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function creatorFieldDisplayValue(fieldValue) {
  if (fieldValue === null || fieldValue === undefined) return "";
  if (typeof fieldValue === "string" || typeof fieldValue === "number" || typeof fieldValue === "boolean") {
    return String(fieldValue);
  }
  if (typeof fieldValue === "object") {
    return (
      fieldValue.display_value ||
      fieldValue.zc_display_value ||
      fieldValue.Display_Value ||
      fieldValue.ZC_Display_Value ||
      ""
    ).toString();
  }
  return "";
}

async function findTechnicianByPhone(phoneE164) {
  const reportLink = (process.env.ZOHO_CREATOR_TECHNICIANS_REPORT_LINK || "technicians_Report").toString().trim();
  const criteria = `phone == "${escapeCreatorCriteriaString(phoneE164)}"`;
  const data = await creatorGetReport(reportLink, { criteria, page: 1, per_page: 1, max_records: 1 });
  const rows = data && Array.isArray(data.data) ? data.data : [];
  return rows[0] || null;
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "acs-ai-backend",
    status: "running"
  });
});

// ----------------------------
// Mobile (FlutterFlow) Auth: Phone + OTP via Twilio Verify
// ----------------------------
app.post("/mobile/auth/start", async (req, res) => {
  try {
    const serviceSid = (process.env.TWILIO_VERIFY_SERVICE_SID || "").toString().trim();
    if (!serviceSid) {
      return res.status(500).json({ ok: false, error: "Server missing TWILIO_VERIFY_SERVICE_SID." });
    }
    if (!twilioClient) {
      return res.status(500).json({ ok: false, error: "Server missing TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN." });
    }
    const phoneE164 = normalizePhoneToE164(req.body && req.body.phone);
    await twilioClient.verify.v2.services(serviceSid).verifications.create({ to: phoneE164, channel: "sms" });
    return res.json({ ok: true });
  } catch (err) {
    console.error("mobile-auth-start error:", err);
    return res.status(400).json({ ok: false, error: err.message || "Failed to start OTP." });
  }
});

app.post("/mobile/auth/verify", async (req, res) => {
  try {
    const serviceSid = (process.env.TWILIO_VERIFY_SERVICE_SID || "").toString().trim();
    if (!serviceSid) {
      return res.status(500).json({ ok: false, error: "Server missing TWILIO_VERIFY_SERVICE_SID." });
    }
    if (!twilioClient) {
      return res.status(500).json({ ok: false, error: "Server missing TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN." });
    }

    const phoneE164 = normalizePhoneToE164(req.body && req.body.phone);
    const code = (req.body && req.body.code ? String(req.body.code) : "").trim();
    if (!code) {
      return res.status(400).json({ ok: false, error: "code is required." });
    }

    const check = await twilioClient.verify.v2.services(serviceSid).verificationChecks.create({ to: phoneE164, code });
    if (!check || String(check.status || "").toLowerCase() !== "approved") {
      return res.status(401).json({ ok: false, error: "Invalid code." });
    }

    // Authorize: phone must exist in your Technicians form.
    // (This avoids random numbers signing in.)
    const tech = await findTechnicianByPhone(phoneE164);
    if (!tech) {
      return res.status(403).json({
        ok: false,
        error: 'Phone not authorized. Add this phone to your "Technicians" form, then try again.'
      });
    }

    const techId = tech.ID;
    const role = (tech.role || "Technician").toString();
    const name = creatorFieldDisplayValue(tech.tech_name) || creatorFieldDisplayValue(tech.tech_name1) || "";

    const token = issueMobileJwt({ techId, phoneE164, role, displayName: name });
    return res.json({
      ok: true,
      token,
      user: {
        tech_id: String(techId),
        role,
        phone: phoneE164,
        name
      }
    });
  } catch (err) {
    console.error("mobile-auth-verify error:", err);
    const status = err.statusCode || 400;
    return res.status(status).json({ ok: false, error: err.message || "Failed to verify OTP." });
  }
});

app.get("/mobile/me", requireMobileJwt, async (req, res) => {
  return res.json({ ok: true, user: req.mobileUser });
});

app.get("/mobile/work-orders", requireMobileJwt, async (req, res) => {
  try {
    const reportLink = (process.env.ZOHO_CREATOR_WORK_ORDERS_REPORT_LINK || "work_orders_Report").toString().trim();
    const mine = (req.query.mine || "").toString().trim().toLowerCase();
    const openOnly = ((req.query.open_only || "true") + "").toString().trim().toLowerCase();

    let criteria = "";
    if (mine === "1" || mine === "true" || mine === "yes") {
      const name = (req.mobileUser && req.mobileUser.name ? String(req.mobileUser.name) : "").trim();
      if (name) {
        criteria = `assigned_tech.contains("${escapeCreatorCriteriaString(name)}")`;
      }
    }
    if (openOnly === "true" || openOnly === "1" || openOnly === "yes") {
      const openCriteria = '(status != "Closed")';
      criteria = criteria ? `(${criteria}) && ${openCriteria}` : openCriteria;
    }

    const data = await creatorGetReport(reportLink, criteria ? { criteria } : {});
    const items = data && Array.isArray(data.data) ? data.data : [];
    return res.json({ ok: true, items });
  } catch (err) {
    console.error("mobile-work-orders error:", err);
    return res.status(500).json({ ok: false, error: err.message || "Server error." });
  }
});

// ----------------------------
// FlutterFlow wrapper endpoints
// ----------------------------
// Header required: x-acs-key: <FF_API_KEY>
function assertValidCreatorPathParams(reportLink, recordId) {
  const link = (reportLink || "").toString().trim();
  const id = (recordId || "").toString().trim();

  // Report link names from Creator exports are typically like: ai_intake_log_Report
  if (!link || !/^[A-Za-z0-9_]+$/.test(link) || link.includes("{") || link.includes("}")) {
    const err = new Error(
      `Invalid reportLink '${link}'. Use the Creator report link name (letters/numbers/underscore only), e.g. ai_intake_log_Report.`
    );
    err.statusCode = 400;
    throw err;
  }

  // Creator record IDs are numeric strings (BIGINT). FlutterFlow misconfig often sends "{recordId}" or blank.
  if (
    !id ||
    id === "undefined" ||
    id === "null" ||
    id.includes("{") ||
    id.includes("}") ||
    !/^[0-9]+$/.test(id)
  ) {
    const err = new Error(
      `Invalid recordId '${id}'. In FlutterFlow, define a String variable named recordId and pass a real numeric Creator record ID (example: 4879112000000152004).`
    );
    err.statusCode = 400;
    throw err;
  }
}

app.get("/ui/report/:reportLink", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const { reportLink } = req.params;
    const data = await creatorGetReport(reportLink, req.query || {});
    return res.json({ ok: true, report: reportLink, data });
  } catch (err) {
    console.error("ui-report error:", err);
    return res.status(500).json({ ok: false, error: err.message || "Server error." });
  }
});

app.get("/ui/report/:reportLink/:recordId", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const { reportLink, recordId } = req.params;
    assertValidCreatorPathParams(reportLink, recordId);
    const data = await creatorGetRecord(reportLink, recordId);
    return res.json({ ok: true, report: reportLink, recordId, data });
  } catch (err) {
    console.error("ui-record-get error:", err);
    const status = err.statusCode || 500;
    return res.status(status).json({ ok: false, error: err.message || "Server error." });
  }
});

app.patch("/ui/report/:reportLink/:recordId", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const { reportLink, recordId } = req.params;
    assertValidCreatorPathParams(reportLink, recordId);
    const updateData = req.body && typeof req.body === "object" ? (req.body.data || req.body) : null;
    if (!updateData || typeof updateData !== "object") {
      return res.status(400).json({ ok: false, error: "Missing JSON body. Send { data: { field: value } }." });
    }
    const data = await creatorUpdateRecord(reportLink, recordId, updateData);
    return res.json({ ok: true, report: reportLink, recordId, data });
  } catch (err) {
    console.error("ui-record-patch error:", err);
    const status = err.statusCode || 500;
    return res.status(status).json({ ok: false, error: err.message || "Server error." });
  }
});

// Query-param variants for FlutterFlow. Some FlutterFlow setups fail to substitute {recordId} path vars reliably.
// Usage:
// - GET   /ui/record/<reportLink>?recordId=<ID>
// - PATCH /ui/record/<reportLink>?recordId=<ID>   body: { "data": { ... } }
app.get("/ui/record/:reportLink", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const { reportLink } = req.params;
    const recordId = (req.query.recordId || req.query.id || "").toString();
    assertValidCreatorPathParams(reportLink, recordId);
    const data = await creatorGetRecord(reportLink, recordId);
    return res.json({ ok: true, report: reportLink, recordId: recordId.toString(), data });
  } catch (err) {
    console.error("ui-record-get(qs) error:", err);
    const status = err.statusCode || 500;
    return res.status(status).json({ ok: false, error: err.message || "Server error." });
  }
});

app.patch("/ui/record/:reportLink", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const { reportLink } = req.params;
    const recordId = (req.query.recordId || req.query.id || "").toString();
    assertValidCreatorPathParams(reportLink, recordId);
    const updateData = req.body && typeof req.body === "object" ? (req.body.data || req.body) : null;
    if (!updateData || typeof updateData !== "object") {
      return res.status(400).json({ ok: false, error: "Missing JSON body. Send { data: { field: value } }." });
    }
    const data = await creatorUpdateRecord(reportLink, recordId, updateData);
    return res.json({ ok: true, report: reportLink, recordId: recordId.toString(), data });
  } catch (err) {
    console.error("ui-record-patch(qs) error:", err);
    const status = err.statusCode || 500;
    return res.status(status).json({ ok: false, error: err.message || "Server error." });
  }
});

// FlutterFlow-safe "update status" endpoint that uses ONLY query parameters.
// This avoids FlutterFlow JSON body variable substitution issues.
//
// Usage:
// - POST /ui/status/<reportLink>?recordId=<ID>&status=<NewStatus>
//
// Examples:
// - POST /ui/status/ai_intake_log_Report?recordId=4879112000000152004&status=Ready
app.post("/ui/status/:reportLink", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const { reportLink } = req.params;
    const recordId = (req.query.recordId || req.query.id || "").toString();
    const statusValue = (req.query.status || "").toString();
    assertValidCreatorPathParams(reportLink, recordId);
    if (!statusValue || statusValue.trim() === "") {
      return res.status(400).json({ ok: false, error: "Missing status query param. Example: ?status=Ready" });
    }
    const data = await creatorUpdateRecord(reportLink, recordId, { status: statusValue });
    return res.json({ ok: true, report: reportLink, recordId: recordId.toString(), data });
  } catch (err) {
    console.error("ui-status-post(qs) error:", err);
    const status = err.statusCode || 500;
    return res.status(status).json({ ok: false, error: err.message || "Server error." });
  }
});

// Body-based variants for FlutterFlow.
// Some FlutterFlow configurations fail to substitute URL params like {recordId}.
//
// Usage:
// - POST  /ui/record-by-body/<reportLink>   body: { "recordId": "<ID>" }
// - PATCH /ui/record-by-body/<reportLink>  body: { "recordId": "<ID>", "data": { ... } }
app.post("/ui/record-by-body/:reportLink", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const { reportLink } = req.params;
    const recordId = req.body && typeof req.body === "object" ? (req.body.recordId || req.body.id || "") : "";
    assertValidCreatorPathParams(reportLink, recordId);
    const data = await creatorGetRecord(reportLink, String(recordId));
    return res.json({ ok: true, report: reportLink, recordId: String(recordId), data });
  } catch (err) {
    console.error("ui-record-by-body(get) error:", err);
    const status = err.statusCode || 500;
    return res.status(status).json({ ok: false, error: err.message || "Server error." });
  }
});

app.patch("/ui/record-by-body/:reportLink", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const { reportLink } = req.params;
    const recordId = req.body && typeof req.body === "object" ? (req.body.recordId || req.body.id || "") : "";
    const updateData = req.body && typeof req.body === "object" ? (req.body.data || null) : null;
    assertValidCreatorPathParams(reportLink, recordId);
    if (!updateData || typeof updateData !== "object") {
      return res.status(400).json({ ok: false, error: "Missing JSON body. Send { recordId, data: { field: value } }." });
    }
    const data = await creatorUpdateRecord(reportLink, String(recordId), updateData);
    return res.json({ ok: true, report: reportLink, recordId: String(recordId), data });
  } catch (err) {
    console.error("ui-record-by-body(patch) error:", err);
    const status = err.statusCode || 500;
    return res.status(status).json({ ok: false, error: err.message || "Server error." });
  }
});

// Convenience queue endpoints (use your report link names from the .ds export)
app.get("/ui/ai-inbox", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const criteria =
      (req.query.criteria || "").toString().trim() ||
      '(status == "Needs Info") || (escalation_flag == true)';
    const data = await creatorGetReport("ai_intake_log_Report", { ...req.query, criteria });
    return res.json({ ok: true, data });
  } catch (err) {
    console.error("ui-ai-inbox error:", err);
    return res.status(500).json({ ok: false, error: err.message || "Server error." });
  }
});

// FlutterFlow-friendly variants of the AI inbox list:
// - /ui/ai-inbox/items returns a top-level "items" array (easy to bind to).
// - /ui/ai-inbox/list returns the array as the root JSON response.
app.get("/ui/ai-inbox/items", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const criteria =
      (req.query.criteria || "").toString().trim() ||
      '(status == "Needs Info") || (escalation_flag == true)';
    const data = await creatorGetReport("ai_intake_log_Report", { ...req.query, criteria });
    const items = data && Array.isArray(data.data) ? data.data : [];
    return res.json({ ok: true, items, meta: { code: data && data.code ? data.code : undefined } });
  } catch (err) {
    console.error("ui-ai-inbox-items error:", err);
    return res.status(500).json({ ok: false, error: err.message || "Server error." });
  }
});

app.get("/ui/ai-inbox/list", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const criteria =
      (req.query.criteria || "").toString().trim() ||
      '(status == "Needs Info") || (escalation_flag == true)';
    const data = await creatorGetReport("ai_intake_log_Report", { ...req.query, criteria });
    const items = data && Array.isArray(data.data) ? data.data : [];
    return res.json(items);
  } catch (err) {
    console.error("ui-ai-inbox-list error:", err);
    return res.status(500).json({ ok: false, error: err.message || "Server error." });
  }
});

app.get("/ui/dispatch-queue", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const criteria =
      (req.query.criteria || "").toString().trim() ||
      '((status == "Approved") || (urgency == "High") || (urgency == "Emergency"))';
    const data = await creatorGetReport("service_requests_Report", { ...req.query, criteria });
    return res.json({ ok: true, data });
  } catch (err) {
    console.error("ui-dispatch-queue error:", err);
    return res.status(500).json({ ok: false, error: err.message || "Server error." });
  }
});

app.get("/ui/money-queue", requireFlutterFlowApiKey, async (req, res) => {
  try {
    const criteria =
      (req.query.criteria || "").toString().trim() ||
      '((status == "Completed") && (books_invoice_id == ""))';
    const data = await creatorGetReport("work_orders_Report", { ...req.query, criteria });
    return res.json({ ok: true, data });
  } catch (err) {
    console.error("ui-money-queue error:", err);
    return res.status(500).json({ ok: false, error: err.message || "Server error." });
  }
});

app.post("/api/ai/create-intake", async (req, res) => {
  try {
    const {
      channel,
      customer_name,
      phone,
      email,
      address,
      service_type,
      urgency,
      request_summary,
      intent,
      chat_session_id
    } = req.body;

    if (!channel || !customer_name || !service_type || !urgency || !request_summary) {
      return res.status(400).json({
        ok: false,
        error: "Missing required intake fields."
      });
    }

    const zohoResult = await createZohoAiIntakeRecord({
      channel: normalizeChannel(channel),
      customer_name,
      phone,
      email,
      address,
      service_type,
      urgency,
      request_summary,
      intent,
      chat_session_id
    });

    return res.json({
      ok: true,
      message: "AI intake received and sent to Zoho Creator.",
      zoho: zohoResult,
      intake: {
        channel: normalizeChannel(channel),
        customer_name,
        phone: phone || "",
        email: email || "",
        address: address || "",
        service_type,
        urgency,
        request_summary,
        intent: intent || "",
        chat_session_id: chat_session_id || ""
      }
    });
  } catch (error) {
    console.error("create-intake error:", error);
    return res.status(500).json({
      ok: false,
      error: "Server error.",
      details: error.message
    });
  }
});

app.post("/api/ai/chat", async (req, res) => {
  try {
    if (!openai) {
      return res.status(500).json({
        ok: false,
        error: "OPENAI_API_KEY is not configured."
      });
    }

    const userMessage = (req.body.message || "").toString().trim();
    const chatSessionId = (req.body.chat_session_id || "").toString().trim();
    const channel = normalizeChannel(req.body.channel);

    if (userMessage === "") {
      return res.status(400).json({
        ok: false,
        error: "Missing message."
      });
    }

    const first = await openai.responses.create({
      model: OPENAI_MODEL,
      input: [
        { role: "system", content: channel === "Phone" ? buildPhoneSystemPrompt() : buildSystemPrompt() },
        { role: "user", content: userMessage }
      ],
      tools: [createIntakeToolSchema()],
      tool_choice: "auto"
    });

    const toolCall = extractFunctionCall(first);

    if (!toolCall) {
      return res.json({
        ok: true,
        intake_created: false,
        reply: responseText(first)
      });
    }

    let args = {};
    try {
      args = JSON.parse(toolCall.arguments || "{}");
    } catch (error) {
      args = {};
    }

    const normalizedPayload = {
      channel,
      customer_name: (args.customer_name || "").toString(),
      phone: (args.phone || "").toString(),
      email: (args.email || "").toString(),
      address: (args.address || "").toString(),
      service_type: mapServiceType(args.service_type),
      urgency: mapUrgency(args.urgency),
      request_summary: (args.request_summary || "").toString(),
      intent: (args.intent || "").toString(),
      chat_session_id: chatSessionId || (args.chat_session_id || "").toString()
    };

    const zohoResult = await createZohoAiIntakeRecord(normalizedPayload);

    const second = await openai.responses.create({
      model: OPENAI_MODEL,
      previous_response_id: first.id,
      input: [
        {
          type: "function_call_output",
          call_id: toolCall.call_id,
          output: JSON.stringify({
            ok: true,
            message: "Intake created.",
            zoho: zohoResult
          })
        }
      ]
    });

    return res.json({
      ok: true,
      intake_created: true,
      reply: responseText(second),
      intake_payload: normalizedPayload,
      zoho: zohoResult
    });
  } catch (error) {
    console.error("ai-chat error:", error);
    return res.status(500).json({
      ok: false,
      error: "AI chat server error.",
      details: error.message
    });
  }
});

// Twilio SMS webhook
// Configure in Twilio Console phone number -> Messaging -> "A message comes in"
// URL: https://<your-railway-domain>/twilio/sms
app.post("/twilio/sms", async (req, res) => {
  try {
    validateTwilioRequestOrThrow(req);

    if (!openai) {
      res.set("Content-Type", "text/xml");
      return res.status(200).send(`<Response><Message>${escapeXml("AI is not configured yet.")}</Message></Response>`);
    }

    const from = (req.body.From || "").toString().trim();
    const bodyText = (req.body.Body || "").toString().trim();

    if (!from || !bodyText) {
      res.set("Content-Type", "text/xml");
      return res.status(200).send(`<Response><Message>${escapeXml("Please send a message with what you need help with.")}</Message></Response>`);
    }

    const sessionId = `sms_${from}`;
    const session = getSmsSession(sessionId);

    // If we already created an intake for this SMS session, don't create another one.
    if (session.intakeCreated) {
      res.set("Content-Type", "text/xml");
      return res
        .status(200)
        .send(
          `<Response><Message>${escapeXml(
            "We already received your request. A team member will follow up shortly. If you need to add details, reply with them and we'll attach them to your request."
          )}</Message></Response>`
        );
    }

    session.history.push({ role: "user", content: bodyText });

    const first = await openai.responses.create({
      model: OPENAI_MODEL,
      input: [
        { role: "system", content: buildPhoneSystemPrompt() },
        ...session.history.map((m) => ({ role: m.role, content: m.content }))
      ],
      tools: [createIntakeToolSchema()],
      tool_choice: "auto"
    });

    const toolCall = extractFunctionCall(first);

    // No tool call: just reply and store assistant response
    if (!toolCall) {
      const reply = responseText(first);
      session.history.push({ role: "assistant", content: reply });
      res.set("Content-Type", "text/xml");
      return res.status(200).send(`<Response><Message>${escapeXml(reply)}</Message></Response>`);
    }

    // Tool call: parse args + normalize + inject phone from Twilio if missing
    let args = {};
    try {
      args = JSON.parse(toolCall.arguments || "{}");
    } catch (error) {
      args = {};
    }

    const transcript = buildTranscriptFromHistory(session.history, 14);

    const normalizedPayload = {
      channel: "Phone",
      customer_name: (args.customer_name || "").toString(),
      phone: (args.phone || from || "").toString(),
      email: (args.email || "").toString(),
      address: (args.address || "").toString(),
      service_type: mapServiceType(args.service_type),
      urgency: mapUrgency(args.urgency),
      request_summary: `${(args.request_summary || "").toString().trim()}\n\nSMS Transcript:\n${transcript}`.trim(),
      intent: (args.intent || "").toString(),
      chat_session_id: sessionId
    };

    const zohoResult = await createZohoAiIntakeRecord(normalizedPayload);
    session.intakeCreated = true;

    // Emergency alert (one per SMS session)
    if (normalizedPayload.urgency === "Emergency" && !session.emergencyAlertSent) {
      session.emergencyAlertSent = true;
      const alertLines = [
        "ACS EMERGENCY LEAD",
        `From: ${from}`,
        normalizedPayload.customer_name ? `Name: ${normalizedPayload.customer_name}` : null,
        normalizedPayload.service_type ? `Service: ${normalizedPayload.service_type}` : null,
        normalizedPayload.address ? `Address: ${normalizedPayload.address}` : null,
        normalizedPayload.request_summary ? `Summary: ${normalizedPayload.request_summary.split("\n")[0]}` : null,
        `Session: ${sessionId}`
      ].filter(Boolean);
      await sendAdminAlertSms(alertLines.join("\n"));
    }

    const second = await openai.responses.create({
      model: OPENAI_MODEL,
      previous_response_id: first.id,
      input: [
        {
          type: "function_call_output",
          call_id: toolCall.call_id,
          output: JSON.stringify({ ok: true, message: "Intake created.", zoho: zohoResult })
        }
      ]
    });

    const reply = responseText(second);
    session.history.push({ role: "assistant", content: reply });

    res.set("Content-Type", "text/xml");
    return res.status(200).send(`<Response><Message>${escapeXml(reply)}</Message></Response>`);
  } catch (error) {
    console.error("twilio-sms error:", error);
    if (error && error.status === 403) {
      res.set("Content-Type", "text/xml");
      return res.status(403).send(`<Response><Message>${escapeXml("Forbidden.")}</Message></Response>`);
    }
    res.set("Content-Type", "text/xml");
    return res.status(200).send(`<Response><Message>${escapeXml("Sorry, something went wrong. Please try again.")}</Message></Response>`);
  }
});

app.listen(port, () => {
  console.log(`acs-ai-backend listening on port ${port}`);
});
