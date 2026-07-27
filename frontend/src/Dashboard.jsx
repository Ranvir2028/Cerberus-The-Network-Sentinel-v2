import { useState, useEffect, useCallback, useRef } from "react";
import { api } from "./api";

const POLL_INTERVAL_MS = 5000;

// A device is considered "active" (currently on the wire) if it was
// last seen within this window. Set relative to the default scapy
// scan interval (60s) with headroom for a couple of missed cycles —
// a device that's simply asleep for one cycle shouldn't flicker to
// "dormant" and back. This is computed client-side from last_seen;
// the backend doesn't need to change to support this.
const ACTIVE_WINDOW_MS = 3 * 60 * 1000;

function isDeviceActive(device) {
  if (!device.last_seen) return false;
  const lastSeenMs = new Date(device.last_seen).getTime();
  if (Number.isNaN(lastSeenMs)) return false;
  return Date.now() - lastSeenMs <= ACTIVE_WINDOW_MS;
}

// A device is "new" for a short window after its first appearance —
// used to trigger a one-time glow rather than a permanent ambient
// effect, per the rule of reserving bright/animated signal for an
// actual state change, not a constant decoration.
const NEW_DEVICE_WINDOW_MS = 2 * 60 * 1000;

function isDeviceNew(device) {
  if (!device.first_seen) return false;
  const firstSeenMs = new Date(device.first_seen).getTime();
  if (Number.isNaN(firstSeenMs)) return false;
  return Date.now() - firstSeenMs <= NEW_DEVICE_WINDOW_MS;
}

// Cerberus mark — a fiercer, more literal three-headed hound than a
// bare circuit-line abstraction, while staying vector/stylized (no
// photorealism, no gore) so it sits comfortably inside the HUD system
// rather than clashing with it. Glowing eyes and small ember accents
// nod at "hellhound" without tipping into graphic content.
function CerberusMark() {
  return (
    <svg viewBox="0 0 48 48" width="44" height="44" fill="none">
      <defs>
        <radialGradient id="eyeGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="var(--cyan)" stopOpacity="1" />
          <stop offset="100%" stopColor="var(--cyan)" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="eyeGlowCopper" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="var(--copper)" stopOpacity="1" />
          <stop offset="100%" stopColor="var(--copper)" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* embers at the base */}
      <path
        d="M14 40 Q16 36 15 33"
        stroke="var(--copper)"
        strokeWidth="1"
        opacity="0.5"
        fill="none"
        strokeLinecap="round"
      />
      <path
        d="M24 41 Q24 37 24 34"
        stroke="var(--copper)"
        strokeWidth="1"
        opacity="0.6"
        fill="none"
        strokeLinecap="round"
      />
      <path
        d="M34 40 Q32 36 33 33"
        stroke="var(--copper)"
        strokeWidth="1"
        opacity="0.5"
        fill="none"
        strokeLinecap="round"
      />

      {/* left head */}
      <path
        d="M9 24 L15 16 L21 22 L19 30 L13 32 L8 28 Z"
        stroke="var(--copper)"
        strokeWidth="1.3"
        fill="rgba(224,145,63,0.08)"
      />
      {/* left fang */}
      <path d="M15 29 L14 33 L16.5 30.5 Z" fill="var(--text)" opacity="0.85" />

      {/* right head */}
      <path
        d="M39 24 L33 16 L27 22 L29 30 L35 32 L40 28 Z"
        stroke="var(--copper)"
        strokeWidth="1.3"
        fill="rgba(224,145,63,0.08)"
      />
      {/* right fang */}
      <path d="M33 29 L34 33 L31.5 30.5 Z" fill="var(--text)" opacity="0.85" />

      {/* center head — larger, dominant */}
      <path
        d="M24 8 L33 18 L30 29 L24 33 L18 29 L15 18 Z"
        stroke="var(--cyan)"
        strokeWidth="1.6"
        fill="var(--cyan-dim)"
      />
      {/* center fangs */}
      <path
        d="M20.5 28 L19.5 33 L22.5 29.5 Z"
        fill="var(--text)"
        opacity="0.9"
      />
      <path
        d="M27.5 28 L28.5 33 L25.5 29.5 Z"
        fill="var(--text)"
        opacity="0.9"
      />

      {/* glowing eyes */}
      <circle cx="24" cy="18" r="4" fill="url(#eyeGlow)" />
      <circle cx="24" cy="18" r="1.5" fill="var(--cyan)" />
      <circle cx="14.5" cy="23" r="2.6" fill="url(#eyeGlowCopper)" />
      <circle cx="14.5" cy="23" r="1" fill="var(--copper)" />
      <circle cx="33.5" cy="23" r="2.6" fill="url(#eyeGlowCopper)" />
      <circle cx="33.5" cy="23" r="1" fill="var(--copper)" />
    </svg>
  );
}

// Minimal outlined bell for the alert dropdown trigger — a thin HUD
// line-icon, not a filled default "notification bell" glyph.
function BellIcon() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none">
      <path
        d="M12 3.5c-3 0-5 2.2-5 5.4v3.1c0 .9-.4 1.8-1.1 2.5L5 15.4h14l-.9-.9c-.7-.7-1.1-1.6-1.1-2.5V8.9c0-3.2-2-5.4-5-5.4Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M10 18a2 2 0 0 0 4 0"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

// Small rotating radar ring used both in the header connection pill
// and per-device in the table — a live sweep for active signals, a
// dim static ring for dormant ones. Kept as one shared component so
// both places always look identical
function RadarRing({ active, size = 13 }) {
  return (
    <span
      className={`radar-ring ${active ? "live" : "dormant"}`}
      style={{ width: size, height: size }}
    />
  );
}

// Minimal outlined gear for the Settings trigger.
function GearIcon() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none">
      <path
        d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path
        d="M19.4 13.5a1.7 1.7 0 0 0 .34 1.87l.06.06a2.06 2.06 0 1 1-2.9 2.9l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56v.17a2.06 2.06 0 1 1-4.12 0v-.09a1.7 1.7 0 0 0-1.11-1.55 1.7 1.7 0 0 0-1.87.34l-.06.06a2.06 2.06 0 1 1-2.9-2.9l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1.03H2a2.06 2.06 0 1 1 0-4.12h.09A1.7 1.7 0 0 0 3.64 7.3a1.7 1.7 0 0 0-.34-1.87l-.06-.06a2.06 2.06 0 1 1 2.9-2.9l.06.06a1.7 1.7 0 0 0 1.87.34H8.1A1.7 1.7 0 0 0 9.13 1.4V1.23a2.06 2.06 0 1 1 4.12 0v.09a1.7 1.7 0 0 0 1.03 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2.06 2.06 0 1 1 2.9 2.9l-.06.06a1.7 1.7 0 0 0-.34 1.87v.06a1.7 1.7 0 0 0 1.56 1.03H21a2.06 2.06 0 1 1 0 4.12h-.09a1.7 1.7 0 0 0-1.51 1.06Z"
        stroke="currentColor"
        strokeWidth="1.1"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function Dashboard() {
  const [status, setStatus] = useState(null);
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [filter, setFilter] = useState("all"); // all | trusted | untrusted
  const [connError, setConnError] = useState(null);
  const [busyMac, setBusyMac] = useState(null);
  const [alertsOpen, setAlertsOpen] = useState(false);
  const alertDropdownRef = useRef(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsDraft, setSettingsDraft] = useState(null);
  const [settingsSecrets, setSettingsSecrets] = useState(null);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [settingsError, setSettingsError] = useState(null);
  const [settingsSaved, setSettingsSaved] = useState(false);

  // Close the alert dropdown on an outside click — standard
  // notification-menu behavior, not something that needs a backdrop
  // overlay for a compact panel like this.
  useEffect(() => {
    if (!alertsOpen) return;
    function handleClickOutside(e) {
      if (
        alertDropdownRef.current &&
        !alertDropdownRef.current.contains(e.target)
      ) {
        setAlertsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [alertsOpen]);

  const refresh = useCallback(async () => {
    try {
      const trustedOnly = filter === "all" ? undefined : filter === "trusted";
      const [statusRes, devicesRes, alertsRes] = await Promise.all([
        api.getFullStatus(),
        api.getDevices(trustedOnly),
        api.getAlerts(20),
      ]);
      setStatus(statusRes);
      setDevices(devicesRes.devices);
      setAlerts(alertsRes.alerts);
      setConnError(null);
    } catch (err) {
      setConnError(err.message);
    }
  }, [filter]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  async function handleTrustToggle(mac, currentlyTrusted) {
    setBusyMac(mac);
    try {
      if (currentlyTrusted) await api.untrustDevice(mac);
      else await api.trustDevice(mac);
      await refresh();
    } catch (err) {
      alert(`Could not update ${mac}: ${err.message}`);
    } finally {
      setBusyMac(null);
    }
  }

  async function handleDelete(mac) {
    if (!confirm(`Remove ${mac} and its scan history? This can't be undone.`))
      return;
    setBusyMac(mac);
    try {
      await api.deleteDevice(mac);
      await refresh();
    } catch (err) {
      alert(`Could not delete ${mac}: ${err.message}`);
    } finally {
      setBusyMac(null);
    }
  }

  async function handleRequestId(mac) {
    setBusyMac(mac);
    try {
      const result = await api.requestDeviceId(mac);
      // A plain prompt() rather than a custom modal — its text is
      // already selectable/copyable by default in every browser,
      // which is all this needs: get the link into the operator's
      // clipboard so they can paste it into whatever they send it
      // through themselves. Cerberus never sends this link anywhere.
      prompt(
        "Copy this link and send it to the device owner yourself " +
          "(text, WhatsApp, in person — Cerberus won't send it for you):",
        result.link,
      );
    } catch (err) {
      alert(`Could not create an identify link: ${err.message}`);
    } finally {
      setBusyMac(null);
    }
  }

  async function handleLearningStart() {
    const hoursStr = prompt(
      "Baseline window length in hours (leave blank for default):",
      "2",
    );
    if (hoursStr === null) return;
    const hours = hoursStr.trim() ? parseInt(hoursStr, 10) : undefined;
    try {
      await api.startLearning(hours);
      await refresh();
    } catch (err) {
      alert(`Could not start learning mode: ${err.message}`);
    }
  }

  async function handleLearningStop() {
    try {
      await api.stopLearning();
      await refresh();
    } catch (err) {
      alert(`Could not stop learning mode: ${err.message}`);
    }
  }

  async function handleDeleteAlert(id) {
    try {
      await api.deleteAlert(id);
      await refresh();
    } catch (err) {
      alert(`Could not delete alert: ${err.message}`);
    }
  }

  async function handleClearAlerts() {
    if (!confirm("Clear all alert history? This can't be undone.")) return;
    try {
      await api.clearAlerts();
      await refresh();
    } catch (err) {
      alert(`Could not clear alerts: ${err.message}`);
    }
  }

  async function openSettings() {
    setSettingsError(null);
    setSettingsSaved(false);
    try {
      const data = await api.getSettings();
      setSettingsDraft(data.editable);
      setSettingsSecrets(data.secrets);
      setSettingsOpen(true);
    } catch (err) {
      alert(`Could not load settings: ${err.message}`);
    }
  }

  function updateDraft(key, value) {
    setSettingsDraft((prev) => ({ ...prev, [key]: value }));
    setSettingsSaved(false);
  }

  async function handleSaveSettings() {
    setSettingsSaving(true);
    setSettingsError(null);
    try {
      const saved = await api.updateSettings(settingsDraft);
      setSettingsDraft(saved);
      setSettingsSaved(true);
    } catch (err) {
      setSettingsError(err.message);
    } finally {
      setSettingsSaving(false);
    }
  }

  const devCounts = status?.devices || { total: 0, trusted: 0, untrusted: 0 };
  const alertCounts = status?.alerts || {
    total: 0,
    new_unknown: 0,
    returning_unknown: 0,
  };
  const learning = status?.learning_mode;
  const scan = status?.scan;
  const learningActive = !!learning?.active;

  const activeCount = devices.filter(isDeviceActive).length;

  return (
    <div className="app">
      {/* ---------------- Header Sentinel Bar ---------------- */}
      <header className="header">
        <div className="brand">
          <div className="brand-mark">
            <CerberusMark />
          </div>
          <div>
            <div className="brand-name">Cerberus</div>
            <div className="brand-sub">network sentinel</div>
          </div>
        </div>

        <div className="hud-readouts">
          <div className="hud-stat">
            <span className="hud-label">System</span>
            <span className={`hud-value ${connError ? "err" : "ok"}`}>
              {connError ? "Offline" : "Online"}
            </span>
          </div>
          <div className="hud-stat">
            <span className="hud-label">Network</span>
            <span className="hud-value mono">{scan?.networks?.[0] || "—"}</span>
          </div>
          <div className="hud-stat">
            <span className="hud-label">Devices</span>
            <span className="hud-value">{devCounts.total}</span>
          </div>
          <div className="hud-stat">
            <span className="hud-label">Scan</span>
            <span className={`hud-value ${scan?.running ? "ok" : ""}`}>
              {scan?.running ? "Active" : "Idle"}
            </span>
          </div>
        </div>

        <div className="header-right">
          <button
            className="icon-header-btn"
            onClick={openSettings}
            aria-label="Settings"
          >
            <GearIcon />
          </button>

          <div className="alert-bell-wrap" ref={alertDropdownRef}>
            <button
              className={`alert-bell ${alertCounts.total > 0 ? "has-alerts" : ""}`}
              onClick={() => setAlertsOpen((o) => !o)}
              aria-label="Alert feed"
            >
              <BellIcon />
              {alertCounts.total > 0 && (
                <span className="alert-badge">
                  {alertCounts.total > 99 ? "99+" : alertCounts.total}
                </span>
              )}
            </button>
            {alertsOpen && (
              <div className="alert-dropdown">
                <div className="alert-dropdown-header">
                  <span className="panel-title">Alert feed</span>
                  {alerts.length > 0 && (
                    <button
                      className="text-link-btn"
                      onClick={handleClearAlerts}
                    >
                      Clear all
                    </button>
                  )}
                </div>
                <div className="alert-dropdown-body">
                  {alerts.length === 0 ? (
                    <div className="empty-state">No alerts fired yet.</div>
                  ) : (
                    alerts.map((a) => (
                      <div className="alert-item" key={a.id}>
                        <div className="alert-head">
                          <span className="alert-verdict">
                            {a.verdict.replace("_", " ")}
                          </span>
                          <span className="alert-item-right">
                            <span className="alert-time">
                              {a.fired_at?.slice(11, 16)}
                            </span>
                            <button
                              className="alert-delete-btn"
                              onClick={() => handleDeleteAlert(a.id)}
                              aria-label="Delete this alert"
                              title="Delete this alert"
                            >
                              ×
                            </button>
                          </span>
                        </div>
                        <div className="alert-summary">{a.message_summary}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="conn-pill">
            <RadarRing active={!connError} size={14} />
            {connError ? "Connection lost" : "Backend reachable"}
          </div>
        </div>
      </header>

      {/* Scan-status strip — replaces the old always-on decorative
          waveform. Now tied to REAL state: a moving sweep only while
          a scan is actually in progress, a flat still line otherwise.
          Bright/animated signal reserved for an actual active state,
          not permanent decoration. */}
      <div className={`scan-strip ${scan?.running ? "scanning" : ""}`}>
        <div className="scan-strip-fill" />
      </div>

      {connError && (
        <div
          className="panel"
          style={{ padding: 16, marginBottom: 20, borderColor: "var(--alert)" }}
        >
          Can't reach the Cerberus API — {connError}. Check that
          cerberus_main.py is running and VITE_API_BASE_URL / VITE_API_KEY in
          your .env match it.
        </div>
      )}

      <section className="stats">
        <div className="stat-card">
          <div className="stat-label">Devices seen</div>
          <div className="stat-value">{devCounts.total}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Active now</div>
          <div className="stat-value trust-color">{activeCount}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Untrusted</div>
          <div className="stat-value alert-color">{devCounts.untrusted}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Alerts fired</div>
          <div className="stat-value">{alertCounts.total}</div>
        </div>
      </section>

      {/* ---------------- 2-column tactical grid ---------------- */}
      <div className="tactical-grid">
        {/* ---------- Left: Tactical Command rail ---------- */}
        <aside
          className={`tactical-rail ${learningActive ? "learning-active" : ""}`}
        >
          <div className="rail-section">
            <div className="rail-label">// Filter</div>
            <nav className="rail-nav">
              {["all", "trusted", "untrusted"].map((f) => (
                <button
                  key={f}
                  className={`rail-nav-item ${filter === f ? "active" : ""}`}
                  onClick={() => setFilter(f)}
                >
                  {f[0].toUpperCase() + f.slice(1)}
                </button>
              ))}
            </nav>
          </div>

          <div className="rail-section rail-learning">
            <div className="rail-label">// Learning mode</div>
            <div className="learning-toggle-row">
              <button
                className={`toggle-switch ${learningActive ? "on" : ""}`}
                onClick={
                  learningActive ? handleLearningStop : handleLearningStart
                }
                aria-label="Toggle learning mode"
              >
                <span className="toggle-knob" />
              </button>
              <span className="toggle-state-label">
                {learningActive ? "Active" : "Off"}
              </span>
            </div>
            {learningActive ? (
              <div className="learning-remaining">{learning.remaining_str}</div>
            ) : (
              <div className="hint-text">
                Use after moving to a new network — won't restart on its own.
              </div>
            )}
          </div>
        </aside>

        {/* ---------- Center: Device Monitor ---------- */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Device monitor</span>
          </div>
          <div className="panel-body">
            {devices.length === 0 ? (
              <div className="empty-state">
                No devices match this filter yet.
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>IP</th>
                    <th>Vendor</th>
                    <th>Status</th>
                    <th>Trust</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => {
                    const active = isDeviceActive(d);
                    const isNew = isDeviceNew(d);
                    return (
                      <tr key={d.mac} className={isNew ? "is-new" : ""}>
                        <td>
                          <div className="device-name">
                            <RadarRing active={active} />
                            {d.label || d.hostname || d.model || d.mac}
                          </div>
                          <div className="device-sub">{d.mac}</div>
                        </td>
                        <td className="mono">{d.ip}</td>
                        <td>{d.vendor || "Unknown"}</td>
                        <td>
                          <span
                            className={`status-badge ${active ? "active" : "dormant"}`}
                          >
                            {active ? "Active" : "Dormant"}
                          </span>
                        </td>
                        <td>
                          <span
                            className={`trust-badge ${d.trusted ? "trusted" : "untrusted"}`}
                          >
                            {d.trusted ? "Trusted" : "Untrusted"}
                          </span>
                        </td>
                        <td>
                          <div className="row-actions">
                            {!d.label && (
                              <button
                                className="icon-btn"
                                disabled={busyMac === d.mac}
                                onClick={() => handleRequestId(d.mac)}
                                title="Create a link asking whoever owns this device to name it"
                              >
                                Request ID
                              </button>
                            )}
                            <button
                              className={`icon-btn ${d.trusted ? "danger" : "safe"}`}
                              disabled={busyMac === d.mac}
                              onClick={() =>
                                handleTrustToggle(d.mac, d.trusted)
                              }
                            >
                              {d.trusted ? "Untrust" : "Trust"}
                            </button>
                            <button
                              className="icon-btn danger"
                              disabled={busyMac === d.mac}
                              onClick={() => handleDelete(d.mac)}
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {settingsOpen && settingsDraft && (
        <div className="modal-overlay" onClick={() => setSettingsOpen(false)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="panel-title">Settings</span>
              <button
                className="modal-close"
                onClick={() => setSettingsOpen(false)}
              >
                ×
              </button>
            </div>

            <div className="modal-body">
              <p className="settings-restart-note">
                Changes here are saved to config.json immediately, but most take
                effect only after you restart Cerberus — there's no live-reload
                for running scan/discovery workers yet.
              </p>

              <div className="settings-group">
                <div className="settings-group-label">
                  Scan timing (seconds)
                </div>
                <label className="settings-row">
                  <span>ARP sweep interval</span>
                  <input
                    type="number"
                    value={settingsDraft.scapy_interval}
                    onChange={(e) =>
                      updateDraft(
                        "scapy_interval",
                        parseInt(e.target.value, 10) || 0,
                      )
                    }
                  />
                </label>
                <label className="settings-row">
                  <span>Nmap quick scan interval</span>
                  <input
                    type="number"
                    value={settingsDraft.nmap_quick_interval}
                    onChange={(e) =>
                      updateDraft(
                        "nmap_quick_interval",
                        parseInt(e.target.value, 10) || 0,
                      )
                    }
                  />
                </label>
                <label className="settings-row">
                  <span>Nmap aggressive scan interval</span>
                  <input
                    type="number"
                    value={settingsDraft.nmap_aggressive_interval}
                    onChange={(e) =>
                      updateDraft(
                        "nmap_aggressive_interval",
                        parseInt(e.target.value, 10) || 0,
                      )
                    }
                  />
                </label>
                <label className="settings-row">
                  <span>Aggressive scan worker threads</span>
                  <input
                    type="number"
                    value={settingsDraft.aggressive_workers}
                    onChange={(e) =>
                      updateDraft(
                        "aggressive_workers",
                        parseInt(e.target.value, 10) || 0,
                      )
                    }
                  />
                </label>
              </div>

              <div className="settings-group">
                <div className="settings-group-label">Discovery sources</div>
                {[
                  ["mdns_enabled", "mdns_interval", "mDNS discovery"],
                  ["dhcp_enabled", "dhcp_drain_interval", "DHCP sniffing"],
                  ["ssdp_enabled", "ssdp_interval", "SSDP / UPnP discovery"],
                  ["llmnr_enabled", "llmnr_interval", "LLMNR discovery"],
                ].map(([enabledKey, intervalKey, name]) => (
                  <div
                    className="settings-row settings-row-toggle"
                    key={enabledKey}
                  >
                    <span>{name}</span>
                    <div className="settings-row-controls">
                      <input
                        type="number"
                        value={settingsDraft[intervalKey]}
                        disabled={!settingsDraft[enabledKey]}
                        onChange={(e) =>
                          updateDraft(
                            intervalKey,
                            parseInt(e.target.value, 10) || 0,
                          )
                        }
                      />
                      <button
                        className={`toggle-switch small ${settingsDraft[enabledKey] ? "on" : ""}`}
                        onClick={() =>
                          updateDraft(enabledKey, !settingsDraft[enabledKey])
                        }
                      >
                        <span className="toggle-knob" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              <div className="settings-group">
                <div className="settings-group-label">
                  Learning &amp; alerts
                </div>
                <label className="settings-row">
                  <span>Default learning-mode window (hours)</span>
                  <input
                    type="number"
                    value={settingsDraft.learning_mode_hours}
                    onChange={(e) =>
                      updateDraft(
                        "learning_mode_hours",
                        parseInt(e.target.value, 10) || 0,
                      )
                    }
                  />
                </label>
                <label className="settings-row">
                  <span>Alert cooldown (minutes)</span>
                  <input
                    type="number"
                    value={settingsDraft.alert_cooldown_minutes}
                    onChange={(e) =>
                      updateDraft(
                        "alert_cooldown_minutes",
                        parseInt(e.target.value, 10) || 0,
                      )
                    }
                  />
                </label>
                <div className="settings-row settings-row-toggle">
                  <span>Email alerts enabled</span>
                  <button
                    className={`toggle-switch small ${settingsDraft.email_alerts_enabled ? "on" : ""}`}
                    onClick={() =>
                      updateDraft(
                        "email_alerts_enabled",
                        !settingsDraft.email_alerts_enabled,
                      )
                    }
                  >
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>

              <div className="settings-group">
                <div className="settings-group-label">
                  Secrets — configured via .env only
                </div>
                {settingsSecrets && (
                  <table className="secrets-status-table">
                    <tbody>
                      <tr>
                        <td>SMTP credentials</td>
                        <td
                          className={
                            settingsSecrets.smtp_configured ? "yes" : "no"
                          }
                        >
                          {settingsSecrets.smtp_configured
                            ? "Configured"
                            : "Not set"}
                        </td>
                      </tr>
                      <tr>
                        <td>API secret</td>
                        <td
                          className={
                            settingsSecrets.api_secret_configured ? "yes" : "no"
                          }
                        >
                          {settingsSecrets.api_secret_configured
                            ? "Configured"
                            : "Not set"}
                        </td>
                      </tr>
                      <tr>
                        <td>Trust-link secret</td>
                        <td
                          className={
                            settingsSecrets.link_secret_explicitly_set
                              ? "yes"
                              : "no"
                          }
                        >
                          {settingsSecrets.link_secret_explicitly_set
                            ? "Configured"
                            : "Auto-generated (temporary)"}
                        </td>
                      </tr>
                      <tr>
                        <td>Router credentials</td>
                        <td
                          className={
                            settingsSecrets.router_credentials_configured
                              ? "yes"
                              : "no"
                          }
                        >
                          {settingsSecrets.router_credentials_configured
                            ? "Configured"
                            : "Not set"}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                )}
              </div>

              {settingsError && (
                <p className="settings-error">{settingsError}</p>
              )}
              {settingsSaved && <p className="settings-saved">Saved.</p>}
            </div>

            <div className="modal-footer">
              <button
                className="btn primary"
                disabled={settingsSaving}
                onClick={handleSaveSettings}
              >
                {settingsSaving ? "Saving..." : "Save settings"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
