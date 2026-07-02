import { useState, useEffect, useCallback } from "react";
import { api } from "./api";

const POLL_INTERVAL_MS = 5000;

// Cerberus mark — three-headed hound reduced to angular circuit-line
// geometry. Deliberately not a cute/illustrated dog: this reads as a
// technical emblem (think squadron insignia or a targeting reticle),
// consistent with the HUD identity rather than a mascot logo.
function CerberusMark() {
  return (
    <svg viewBox="0 0 48 48" width="46" height="46" fill="none">
      <polygon
        points="24,3 44,15 44,33 24,45 4,33 4,15"
        stroke="var(--cyan)"
        strokeWidth="1.2"
        opacity="0.5"
      />
      {/* center head */}
      <path
        d="M24 14 L30 22 L27 30 L21 30 L18 22 Z"
        stroke="var(--cyan)"
        strokeWidth="1.6"
        fill="var(--cyan-dim)"
      />
      {/* left head */}
      <path
        d="M13 19 L18 24 L16 31 L11 29 L9 22 Z"
        stroke="var(--copper)"
        strokeWidth="1.4"
        fill="rgba(224,145,63,0.10)"
      />
      {/* right head */}
      <path
        d="M35 19 L30 24 L32 31 L37 29 L39 22 Z"
        stroke="var(--copper)"
        strokeWidth="1.4"
        fill="rgba(224,145,63,0.10)"
      />
      {/* three eyes */}
      <circle cx="24" cy="21" r="1.4" fill="var(--cyan)" />
      <circle cx="14.5" cy="24" r="1.1" fill="var(--copper)" />
      <circle cx="33.5" cy="24" r="1.1" fill="var(--copper)" />
    </svg>
  );
}

export default function App() {
  const [status, setStatus] = useState(null);
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [filter, setFilter] = useState("all"); // all | trusted | untrusted
  const [connError, setConnError] = useState(null);
  const [busyMac, setBusyMac] = useState(null);

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

  const devCounts = status?.devices || { total: 0, trusted: 0, untrusted: 0 };
  const alertCounts = status?.alerts || {
    total: 0,
    new_unknown: 0,
    returning_unknown: 0,
  };
  const learning = status?.learning_mode;
  const scan = status?.scan;

  return (
    <div className="app">
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
        <div className="conn-pill">
          <span className={`radar ${connError ? "down" : "live"}`} />
          {connError
            ? "Connection lost"
            : scan?.attached
              ? "Scanner attached"
              : "Backend reachable"}
        </div>
      </header>

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
          <div className="stat-label">Trusted</div>
          <div className="stat-value trust-color">{devCounts.trusted}</div>
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

      <div className="main-grid">
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Devices</span>
            <div className="filter-tabs">
              {["all", "trusted", "untrusted"].map((f) => (
                <button
                  key={f}
                  className={`filter-tab ${filter === f ? "active" : ""}`}
                  onClick={() => setFilter(f)}
                >
                  {f[0].toUpperCase() + f.slice(1)}
                </button>
              ))}
            </div>
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
                    <th>Trust</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.mac}>
                      <td>
                        <div className="device-name">
                          <span className="pulse-dot" />
                          {d.label || d.hostname || d.mac}
                        </div>
                        <div className="device-sub">{d.mac}</div>
                      </td>
                      <td className="mono">{d.ip}</td>
                      <td>{d.vendor || "Unknown"}</td>
                      <td>
                        <span
                          className={`trust-badge ${d.trusted ? "trusted" : "untrusted"}`}
                        >
                          {d.trusted ? "Trusted" : "Untrusted"}
                        </span>
                      </td>
                      <td>
                        <div className="row-actions">
                          <button
                            className={`icon-btn ${d.trusted ? "danger" : "safe"}`}
                            disabled={busyMac === d.mac}
                            onClick={() => handleTrustToggle(d.mac, d.trusted)}
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
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "var(--gap)",
          }}
        >
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Learning mode</span>
            </div>
            <div className="learning-box">
              <div className="learning-status-line">
                <span
                  className={`dot ${learning?.active ? "learning" : ""}`}
                  style={
                    !learning?.active ? { background: "var(--text-faint)" } : {}
                  }
                />
                {learning?.active
                  ? "Active — auto-trusting new devices"
                  : "Not active"}
              </div>
              {learning?.active && (
                <div className="learning-remaining">
                  {learning.remaining_str}
                </div>
              )}
              {learning?.active ? (
                <button className="btn stop" onClick={handleLearningStop}>
                  Stop now
                </button>
              ) : (
                <button className="btn primary" onClick={handleLearningStart}>
                  Start baseline window
                </button>
              )}
              <div className="hint-text">
                Use this after moving to a new network location — it won't
                restart automatically on its own.
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Recent alerts</span>
            </div>
            <div className="panel-body">
              {alerts.length === 0 ? (
                <div className="empty-state">No alerts fired yet.</div>
              ) : (
                alerts.map((a, i) => (
                  <div className="alert-item" key={i}>
                    <div className="alert-head">
                      <span className="alert-verdict">
                        {a.verdict.replace("_", " ")}
                      </span>
                      <span className="alert-time">
                        {a.fired_at?.slice(11, 16)}
                      </span>
                    </div>
                    <div className="alert-summary">{a.message_summary}</div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
