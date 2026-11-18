import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { useAuth } from "./hooks/useAuth";
import { DatasetInspection } from "./pages/DatasetInspection";
import { DatasetInventory } from "./pages/DatasetInventory";
import { Incidents } from "./pages/Incidents";
import { Login } from "./pages/Login";
import { ModelEvaluation } from "./pages/ModelEvaluation";
import { Overview } from "./pages/Overview";
import { Reports } from "./pages/Reports";
import { SecurityFindings } from "./pages/SecurityFindings";
import { Settings } from "./pages/Settings";
import { SupplyChainGraph } from "./pages/SupplyChainGraph";
import { TrainingRuns } from "./pages/TrainingRuns";

export function App() {
  const { user, ready } = useAuth();
  if (!ready) return <Loading label="Starting TrustTrain…" />;
  if (!user) return <Login />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="datasets" element={<DatasetInventory />} />
        <Route path="inspection" element={<DatasetInspection />} />
        <Route path="inspection/:datasetId" element={<DatasetInspection />} />
        <Route path="findings" element={<SecurityFindings />} />
        <Route path="evaluation" element={<ModelEvaluation />} />
        <Route path="supply-chain" element={<SupplyChainGraph />} />
        <Route path="training" element={<TrainingRuns />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:incidentId" element={<Incidents />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
