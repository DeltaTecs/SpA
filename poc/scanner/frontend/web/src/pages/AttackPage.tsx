import { useState } from "react";
import { CreatePlanTab } from "../components/attack/CreatePlanTab";

type AttackTab = "create-plan" | "overview";

export function AttackPage() {
  const [tab, setTab] = useState<AttackTab>("create-plan");

  return (
    <div className="page">
      <header className="page__header">
        <h1>Attack</h1>
      </header>

      <div className="attack-tabs">
        <button
          type="button"
          className={`tab${tab === "create-plan" ? " tab--active" : ""}`}
          onClick={() => setTab("create-plan")}
        >
          Create Plan
        </button>
        <button
          type="button"
          className={`tab${tab === "overview" ? " tab--active" : ""}`}
          onClick={() => setTab("overview")}
        >
          Overview
        </button>
      </div>

      {tab === "create-plan" ? <CreatePlanTab /> : <Overview />}
    </div>
  );
}

function Overview() {
  return (
    <div className="placeholder">
      <div className="placeholder__icon">🛠️</div>
      <h2>Attack tooling — coming soon</h2>
      <p>
        AI-powered active analysis and scan execution will live here, driven by the plans
        created from recorded traffic.
      </p>
    </div>
  );
}
