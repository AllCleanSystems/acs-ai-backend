const SERVICE_TYPE_MAP = {
  "carpet cleaning": "Carpet Cleaning",
  "carpet clean": "Carpet Cleaning",
  "house wash": "House Wash",
  "pressure washing": "Pressure Washing",
  "roof cleaning": "Roof Cleaning",
  "window cleaning": "Window Cleaning",
  "gutter cleaning": "Gutter Cleaning",
  "commercial cleaning": "Commercial Cleaning"
};

const URGENCY_MAP = {
  emergency: "Emergency",
  high: "High",
  normal: "Normal",
  low: "Low"
};

function normalizeText(value) {
  if (!value) return "";
  return String(value).trim().toLowerCase();
}

function mapServiceType(inputValue) {
  const key = normalizeText(inputValue);
  return SERVICE_TYPE_MAP[key] || inputValue;
}

function mapUrgency(inputValue) {
  const key = normalizeText(inputValue);
  return URGENCY_MAP[key] || "Normal";
}

module.exports = {
  mapServiceType,
  mapUrgency
};
