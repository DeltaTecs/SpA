import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./layout/Layout";
import { AnalysisQueuePage } from "./pages/AnalysisQueuePage";
import { DashboardPage } from "./pages/DashboardPage";
import { ExplorerPage } from "./pages/ExplorerPage";
import { TestPlannerPage } from "./pages/TestPlannerPage";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="explorer" element={<ExplorerPage />} />
          <Route path="test-planner" element={<TestPlannerPage />} />
          <Route path="analysis-queue" element={<AnalysisQueuePage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
