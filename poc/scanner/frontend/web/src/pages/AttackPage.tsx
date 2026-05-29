import { useCallback, useState } from "react";
import { CreatePlanTab } from "../components/attack/CreatePlanTab";
import { PentestTab } from "../components/attack/PentestTab";
import type { PentestPlan } from "../components/attack/types";

type AttackTab = "create-plan" | "pentest" | "overview";

export function AttackPage() {
  const [tab, setTab] = useState<AttackTab>("create-plan");
  const [plan, setPlan] = useState<PentestPlan | null>(null);
  const pentestReady = plan !== null && plan.items.length > 0;

  // Stable identity so CreatePlanTab's plan-ready effect does not refire each render.
  const handlePlanReady = useCallback((next: PentestPlan | null) => setPlan(next), []);

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
          className={`tab${tab === "pentest" ? " tab--active" : ""}`}
          onClick={() => setTab("pentest")}
          disabled={!pentestReady}
          title={pentestReady ? undefined : "Create a plan first (run an analysis)"}
        >
          Pentest
        </button>
        <button
          type="button"
          className={`tab${tab === "overview" ? " tab--active" : ""}`}
          onClick={() => setTab("overview")}
        >
          Overview
        </button>
      </div>

      {/* Tabs stay mounted so the analysis/pentest jobs and their polling survive
          tab switches; visibility is toggled rather than unmounting. */}
      <div hidden={tab !== "create-plan"}>
        <CreatePlanTab
          onPlanReady={handlePlanReady}
          pentestReady={pentestReady}
          onGoToPentest={() => setTab("pentest")}
        />
      </div>
      {plan && (
        <div hidden={tab !== "pentest"}>
          <PentestTab plan={plan} />
        </div>
      )}
      {tab === "overview" && <Overview />}
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
