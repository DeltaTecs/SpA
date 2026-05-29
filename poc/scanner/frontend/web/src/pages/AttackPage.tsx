export function AttackPage() {
  // Placeholder. The AI-powered attack/scan orchestration will mount here and
  // talk to the backend (scanner/backend/llm + MCP tools) via the frontend
  // server's /api/* layer. Keep new attack UI in components/attack/*.
  return (
    <div className="page">
      <header className="page__header">
        <h1>Attack</h1>
      </header>
      <div className="placeholder">
        <div className="placeholder__icon">🛠️</div>
        <h2>Attack tooling — coming soon</h2>
        <p>
          This page will host AI-powered vulnerability scans and active analysis of the
          remote service, driven by the recorded traffic.
        </p>
      </div>
    </div>
  );
}
