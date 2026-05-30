import { Outlet } from "react-router-dom";
import { AnalysisQueueProvider } from "../state/AnalysisQueueContext";
import { Sidebar } from "./Sidebar";

export function Layout() {
  return (
    // The queue provider lives here (outside the routed Outlet) so the queue and
    // its in-flight investigations survive navigation between pages.
    <AnalysisQueueProvider>
      <div className="app-shell">
        <Sidebar />
        <main className="app-main">
          <Outlet />
        </main>
      </div>
    </AnalysisQueueProvider>
  );
}
