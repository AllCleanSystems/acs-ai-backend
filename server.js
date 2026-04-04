const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");

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

    return res.json({
      ok: true,
      message: "AI intake received.",
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
      error: "Server error."
    });
  }
});

app.listen(port, () => {
  console.log(`acs-ai-backend listening on port ${port}`);
});
