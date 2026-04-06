const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const fetch = require("node-fetch");
const OpenAI = require("openai");

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;
const REQUEST_TIMEOUT_MS = 15000;
const RETRY_DELAY_MS = 1200;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";

app.use(cors());
app.use(express.json());

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

const SERVICE_TYPE_MAP = {
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
  return [408, 429, 500, 502, 503, 504].includes(status);
}

function isRetryableNetworkError(error) {
  const code = error && error.code ? String(error.code) : "";
  const message = error && error.message ? String(error.message).toLowerCase() : "";
  return (
    code === "ETIMEDOUT" ||
    code === "ECONNRESET" ||
    code === "EAI_AGAIN" ||
    message.includes("timeout") ||
    message.includes("network")
  );
}

function normalizeText(value) {
  if (!value) return "";
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

function buildSystemPrompt() {
  return [
    "You are the ACS website intake assistant.",
    "Collect details for a service intake.",
    "Required before creating intake:",
    "- customer_name",
    "- service_type",
    "- urgency",
    "- request_summary",
    "- at least one contact method (phone or email)",
    "Rules:",
    "- Keep responses concise and friendly.",
    "- Ask short follow-up questions only when required.",
    "- Do not promise pricing or appointment times.",
    "- When required fields are present, call create_ai_intake."
  ].join("\n");
}

function createIntakeToolSchema() {
  return {
    type: "function",
    name: "create_ai_intake",
    description: "Create an AI intake record in Zoho Creator.",
    parameters: {
      type: "object",
      properties: {
        channel: { type: "string", enum: ["Website Chat"] },
        customer_name: { type: "string" },
        phone: { type: "string" },
        email: { type: "string" },
        address: { type: "string" },
        service_type: { type: "string" },
        urgency: { type: "string", enum: ["Emergency", "High", "Normal", "Low"] },
        request_summary: { type: "string" },
        intent: { type: "string" },
        ai_confidence: { type: "number" },
        chat_session_id: { type: "string" }
      },
      required: ["channel", "customer_name", "service_type", "urgency", "request_summary"]
    }
  };
}

function extractFunctionCall(response) {
  if (!response || !Array.isArray(response.output)) return null;
  for (const item of response.output) {
    if (item.type === "function_call" && item.name === "create_ai_intake") return item;
  }
  return null;
}

function responseText(response) {
  if (response && typeof response.output_text === "string" && response.output_text.trim() !== "") {
    return response.output_text;
  }
  return "Thanks. I can help with that. Please share your name and best contact info.";
}

async function safeJson(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
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

  const response = await fetchWithRetry(
    "https://accounts.zoho.com/oauth/v2/token",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString()
    },
    "zoho-token"
  );

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
    Chat_Session_ID: payload.chat_session_id || "",
    AI_Status: "New"
  };

  const conf = Number(payload.ai_confidence);
  if (!Number.isNaN(conf)) {
    dataPayload.AI_Confidence = conf;
  }

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

  const response = await fetchWithRetry(
    url,
    {
      method: "POST",
      headers: {
        Authorization: `Zoho-oauthtoken ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ data: dataPayload })
    },
    "zoho-creator-create"
  );

  const data = await safeJson(response);
  if (!response.ok || (data.code && data.code !== 3000)) {
    throw new Error(`Zoho Creator create record error: ${JSON.stringify(data)}`);
  }

  return data;
}

app.get("/", (req, res) => {
  res.json({ ok: true, service: "acs-ai-backend", status: "running" });
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
      return res.status(400).json({ ok: false, error: "Missing required intake fields." });
    }

    const normalizedPayload = {
      channel,
      customer_name,
      phone: phone || "",
      email: email || "",
      address: address || "",
      service_type: mapServiceType(service_type),
      urgency: mapUrgency(urgency),
      request_summary,
      intent: intent || "",
      ai_confidence,
      chat_session_id: chat_session_id || ""
    };

    const zohoResult = await createZohoAiIntakeRecord(normalizedPayload);

    return res.json({
      ok: true,
      message: "AI intake received and sent to Zoho Creator.",
      zoho: zohoResult,
      intake: normalizedPayload
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
      return res.status(500).json({ ok: false, error: "OPENAI_API_KEY is not configured." });
    }

    const userMessage = (req.body.message || "").toString().trim();
    const chatSessionId = (req.body.chat_session_id || "").toString().trim();

    if (userMessage === "") {
      return res.status(400).json({ ok: false, error: "Missing message." });
    }

    const first = await openai.responses.create({
      model: OPENAI_MODEL,
      input: [
        { role: "system", content: buildSystemPrompt() },
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
    } catch {
      args = {};
    }

    const parsedConfidence = Number(args.ai_confidence);

    const normalizedPayload = {
      channel: "Website Chat",
      customer_name: (args.customer_name || "").toString(),
      phone: (args.phone || "").toString(),
      email: (args.email || "").toString(),
      address: (args.address || "").toString(),
      service_type: mapServiceType(args.service_type),
      urgency: mapUrgency(args.urgency),
      request_summary: (args.request_summary || "").toString(),
      intent: (args.intent || "").toString(),
      ai_confidence: Number.isNaN(parsedConfidence) ? undefined : parsedConfidence,
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
          output: JSON.stringify({ ok: true, message: "Intake created.", zoho: zohoResult })
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

app.listen(port, () => {
  console.log(`acs-ai-backend listening on port ${port}`);
});
