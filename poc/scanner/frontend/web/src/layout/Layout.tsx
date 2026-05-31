import { Outlet } from "react-router-dom";
import { AnalysisQueueProvider } from "../state/AnalysisQueueContext";
import { GuidedAnalysisProvider } from "../state/GuidedAnalysisContext";
import { Sidebar } from "./Sidebar";

export function Layout() {
  return (
    // Both providers live here (outside the routed Outlet) so the queue's
    // in-flight investigations and the guided chat (and any staged input) survive
    // navigation between pages.
    <AnalysisQueueProvider>
      <GuidedAnalysisProvider>
        <div className="app-shell">
          <Sidebar />
          <main className="app-main">
            <Outlet />
          </main>
        </div>
      </GuidedAnalysisProvider>
    </AnalysisQueueProvider>
  );
}
