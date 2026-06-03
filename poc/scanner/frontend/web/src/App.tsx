import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./layout/Layout";
import { AnalysisQueuePage } from "./pages/AnalysisQueuePage";
import { DashboardPage } from "./pages/DashboardPage";
import { ExplorerPage } from "./pages/ExplorerPage";
import { ExploitQueuePage } from "./pages/ExploitQueuePage";
import { GuidedAnalysisPage } from "./pages/GuidedAnalysisPage";
import { TestPlannerPage } from "./pages/TestPlannerPage";
import { ToolScriptPage } from "./pages/ToolScriptPage";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="explorer" element={<ExplorerPage />} />
          <Route path="test-planner" element={<TestPlannerPage />} />
          <Route path="analysis-queue" element={<AnalysisQueuePage />} />
          <Route path="exploit-queue" element={<ExploitQueuePage />} />
          <Route path="guided-analysis" element={<GuidedAnalysisPage />} />
        </Route>
        {/* Standalone, sidebar-less document opened in a new tab from a result's
            "Tool script" button. */}
        <Route path="tool-script" element={<ToolScriptPage />} />
      </Routes>
    </BrowserRouter>
  );
}
