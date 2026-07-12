import Dashboard from "./Dashboard.jsx";

// Kept deliberately thin. Phase 5 (multi-user auth) will add a login
// check here — e.g. render <Login/> until authenticated, then
// <Dashboard/> — WITHOUT touching a single line inside Dashboard.jsx
// itself. That separation is the entire point of this file existing
// as its own component instead of just being Dashboard directly.
export default function App() {
  return <Dashboard />;
}
