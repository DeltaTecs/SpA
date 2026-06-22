import { Outlet } from "react-router-dom";
import { AnalysisQueueProvider } from "../state/AnalysisQueueContext";
import { ExploitQueueProvider } from "../state/ExploitQueueContext";
import { GuidedAnalysisProvider } from "../state/GuidedAnalysisContext";
import { Sidebar } from "./Sidebar";

export function Layout() {
  return (
    // All queue/chat providers live here (outside the routed Outlet) so their
    // in-flight work and any staged input survive navigation between pages. The
    // Exploit Queue provider also wraps the Analysis Queue page, which enqueues
    // into it via "Send to Exploit Queue".
    <AnalysisQueueProvider>
      <ExploitQueueProvider>
        <GuidedAnalysisProvider>
          <div className="app-shell">
            <Sidebar />
            <main className="app-main">
              <Outlet />
            </main>
          </div>
        </GuidedAnalysisProvider>
      </ExploitQueueProvider>
    </AnalysisQueueProvider>
  );
}
