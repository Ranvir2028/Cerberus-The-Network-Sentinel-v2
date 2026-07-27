// Talks only to the embedded Flask API — same seam discipline as the
// CLI. Never assumes anything about storage/scheduler internals, just
// calls the documented /api/* routes. Base URL comes from Vite env
// vars, see .env.example.

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

// Just reads a fixed build-time env var for now. A future login flow
// would only need to change the body of this one function to pull the
// token from login state instead — every call site below stays
// untouched since they all just call getApiKey().
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
