import { CreatePlanTab } from "../components/attack/CreatePlanTab";

export function TestPlannerPage() {
  return (
    <div className="page">
      <header className="page__header">
        <h1>Test Planner</h1>
      </header>
      <CreatePlanTab />
    </div>
  );
}
