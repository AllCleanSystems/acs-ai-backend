const SERVICE_TYPE_MAP = {
  "carpet cleaning": "Carpet Cleaning",
  "carpet clean": "Carpet Cleaning",

  "window cleaning": "Window Cleaning",

  "commercial cleaning": "Commercial Cleaning",

  "lawn maintenance": "Lawn Maintenance",
  "lawn maintenace": "Lawn Maintenance",
  "lawn service": "Lawn Maintenance",

  "snow removal": "Snow Removal",
  "snow": "Snow Removal",

  "food truck cleaning": "Food Truck Cleaning",
  "truck cleaning": "Food Truck Cleaning",

  "hood cleaning": "Hood Cleaning",
  "kitchen hood cleaning": "Hood Cleaning",

  "other": "Other"
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
  return SERVICE_TYPE_MAP[key] || "Other";
}

function mapUrgency(inputValue) {
  const key = normalizeText(inputValue);
  return URGENCY_MAP[key] || "Normal";
}

module.exports = {
  mapServiceType,
  mapUrgency
};
