// Cerberus Dashboard — API client
//
// Talks ONLY to the embedded Flask API (api/server.py) — same seam
// discipline as the CLI. Never assumes anything about storage/scheduler
// internals; just calls the documented /api/* routes.
//
// Base URL and API key come from Vite env vars (see .env.example).
// VITE_API_KEY must match CERBERUS_API_SECRET in your backend's .env —
// if you didn't set one there, leave this blank too.

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";
const API_KEY = import.meta.env.VITE_API_KEY || "";

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (API_KEY) headers["X-API-Key"] = API_KEY;

  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers });
  const body = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(body.error || `Request failed: ${res.status}`);
  }
  return body;
}

export const api = {
  getFullStatus: () => request("/api/status"),
  getDevices: (trustedOnly) => {
    const q = trustedOnly === undefined ? "" : `?trusted=${trustedOnly}`;
    return request(`/api/devices${q}`);
  },
  getDevice: (mac) => request(`/api/devices/${mac}`),
  trustDevice: (mac) =>
    request(`/api/devices/${mac}/trust`, { method: "POST" }),
  untrustDevice: (mac) =>
    request(`/api/devices/${mac}/untrust`, { method: "POST" }),
  labelDevice: (mac, label) =>
    request(`/api/devices/${mac}/label`, {
      method: "POST",
      body: JSON.stringify({ label }),
    }),
  deleteDevice: (mac) => request(`/api/devices/${mac}`, { method: "DELETE" }),
  getAlerts: (limit = 30) => request(`/api/alerts?limit=${limit}`),
  getLearningStatus: () => request("/api/learning"),
  startLearning: (hours) =>
    request("/api/learning/start", {
      method: "POST",
      body: JSON.stringify(hours ? { hours } : {}),
    }),
  stopLearning: () => request("/api/learning/stop", { method: "POST" }),
};
