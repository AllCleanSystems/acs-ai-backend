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

const body = { data: dataPayload };

