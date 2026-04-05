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

  const body = { data: dataPayload };

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Zoho-oauthtoken ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  const data = await response.json();

  // Zoho can return HTTP 200 with non-3000 code for logical errors.
  if (!response.ok || (data.code && data.code !== 3000)) {
    throw new Error(`Zoho Creator create record error: ${JSON.stringify(data)}`);
  }

  return data;
}
