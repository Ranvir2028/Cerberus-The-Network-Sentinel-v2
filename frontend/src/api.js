// Cerberus Dashboard — API client
//
// Talks ONLY to the embedded Flask API (api/server.py) — same seam
// discipline as the CLI. Never assumes anything about storage/scheduler
// internals; just calls the documented /api/* routes.
//
// Base URL comes from Vite env vars (see .env.example).

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

// Isolated on purpose: right now this just reads a fixed build-time env
// var. Phase 5 (multi-user auth) will replace the BODY of this one
// function with "read the token from login state" — every call site
// below stays completely untouched, since they all just call
// getApiKey() without caring where the value comes from.
function getApiKey() {
  return import.meta.env.VITE_API_KEY || "";
}

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...options.headers };
  const key = getApiKey();
  if (key) headers["X-API-Key"] = key;

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
  getDevice: (mac) => request(`/api/devices/${encodeURIComponent(mac)}`),
  trustDevice: (mac) =>
    request(`/api/devices/${encodeURIComponent(mac)}/trust`, {
      method: "POST",
    }),
  untrustDevice: (mac) =>
    request(`/api/devices/${encodeURIComponent(mac)}/untrust`, {
      method: "POST",
    }),
  labelDevice: (mac, label) =>
    request(`/api/devices/${encodeURIComponent(mac)}/label`, {
      method: "POST",
      body: JSON.stringify({ label }),
    }),
  deleteDevice: (mac) =>
    request(`/api/devices/${encodeURIComponent(mac)}`, { method: "DELETE" }),
  requestDeviceId: (mac) =>
    request(`/api/devices/${encodeURIComponent(mac)}/request-id`, {
      method: "POST",
    }),
  getAlerts: (limit = 30) => request(`/api/alerts?limit=${limit}`),
  deleteAlert: (id) => request(`/api/alerts/${id}`, { method: "DELETE" }),
  clearAlerts: () => request("/api/alerts", { method: "DELETE" }),
  getLearningStatus: () => request("/api/learning"),
  startLearning: (hours) =>
    request("/api/learning/start", {
      method: "POST",
      body: JSON.stringify(hours ? { hours } : {}),
    }),
  stopLearning: () => request("/api/learning/stop", { method: "POST" }),
  getSettings: () => request("/api/settings"),
  updateSettings: (updates) =>
    request("/api/settings", { method: "POST", body: JSON.stringify(updates) }),
};
