const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const fetch = require("node-fetch");

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "acs-ai-backend",
    status: "running"
  });
});

async function getZohoAccessToken() {
  const tokenUrl =
    "https://accounts.zoho.com/oauth/v2/token" +
    `?client_id=${encodeURIComponent(process.env.ZOHO_CLIENT_ID || "")}` +
    `&grant_type=refresh_token` +
    `&client_secret=${encodeURIComponent(process.env.ZOHO_CLIENT_SECRET || "")}` +
    `&refresh_token=${encodeURIComponent(process.env.ZOHO_REFRESH_TOKEN || "")}`;

  const response = await fetch(tokenUrl, {
    method: "POST"
  });

  const data = await response.json();

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

  const url = `https://creator.zoho.com/api/v2/${owner}/${appLink}/form/${formLink}`;

  const body = {
    data: {
      Channel: payload.channel,
      Customer_Name: payload.customer_name,
      Phone: payload.phone || "",
      Email: payload.email || "",
      Address: payload.address || "",
      Service_Type: payload.service_type,
      Urgency: payload.urgency,
      Request_Summary: payload.request_summary,
      Intent: payload.intent || "",
      AI_Confidence: payload.ai_confidence || null,
      Chat_Session_ID: payload.chat_session_id || "",
      AI_Status: "New"
    }
  };

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Zoho-oauthtoken ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(`Zoho Creator create record error: ${JSON.stringify(data)}`);
  }

  return data;
}

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
