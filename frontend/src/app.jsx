import Dashboard from "./Dashboard.jsx";

// Kept thin on purpose — a future login check can render <Login/> until
// authenticated, then <Dashboard/>, without touching a single line
// inside Dashboard.jsx. That's the whole reason this wrapper exists
// instead of just exporting Dashboard directly.
export default function App() {
  return <Dashboard />;
}
