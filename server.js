const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const fetch = require("node-fetch");

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;
const REQUEST_TIMEOUT_MS = 15000;
const RETRY_DELAY_MS = 1200;

app.use(cors());
app.use(express.json());

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

async function getZohoAccessToken() {
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
    throw new Error(`Zoho token error: ${JSON.stringify(data)}`);
  }

  return data.access_token;
}

async function createZohoAiIntakeRecord(payload) {
  const accessToken = await getZohoAccessToken();

  const owner = process.env.ZOHO_CREATOR_OWNER;
  const appLink = process.env.ZOHO_CREATOR_APP_LINK;
  const formLink = "AI_Intake_Log";

  const url = `https://www.zohoapis.com/creator/v2.1/data/${owner}/${appLink}/form/${formLink}`;

  const dataPayload = {
    Channel: payload.channel,
    Customer_Name: payload.customer_name,
    Phone: payload.phone || "",
    Email: payload.email || "",
    Service_Type: payload.service_type,
    Urgency: payload.urgency,
    Request_Summary: payload.request_summary,
    Intent: payload.intent || "",
    AI_Confidence: payload.ai_confidence ?? null,
    Chat_Session_ID: payload.chat_session_id || "",
    AI_Status: "New"
  };

  if (payload.address) {
    dataPayload.Address = {
      address_line_1: payload.address,
      address_line_2: "",
      district_city: "",
      state_province: "",
      postal_Code: "",
      country: "United States"
    };
  }

  const body = {
    data: dataPayload
  };

  const response = await fetchWithRetry(url, {
    method: "POST",
    headers: {
      Authorization: `Zoho-oauthtoken ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  }, "zoho-creator-create");

  const data = await safeJson(response);

  if (!response.ok || (data.code && data.code !== 3000)) {
    throw new Error(`Zoho Creator create record error: ${JSON.stringify(data)}`);
  }

  return data;
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "acs-ai-backend",
    status: "running"
  });
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
      ai_confidence,
      chat_session_id
    } = req.body;

    if (!channel || !customer_name || !service_type || !urgency || !request_summary) {
      return res.status(400).json({
        ok: false,
        error: "Missing required intake fields."
      });
    }

    const zohoResult = await createZohoAiIntakeRecord({
      channel,
      customer_name,
      phone,
      email,
      address,
      service_type,
      urgency,
      request_summary,
      intent,
      ai_confidence,
      chat_session_id
    });

    return res.json({
      ok: true,
      message: "AI intake received and sent to Zoho Creator.",
      zoho: zohoResult,
      intake: {
        channel,
        customer_name,
        phone: phone || "",
        email: email || "",
        address: address || "",
        service_type,
        urgency,
        request_summary,
        intent: intent || "",
        ai_confidence: ai_confidence || null,
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

app.listen(port, () => {
  console.log(`acs-ai-backend listening on port ${port}`);
});
