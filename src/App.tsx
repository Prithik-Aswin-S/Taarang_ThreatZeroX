import { BrowserRouter, Routes, Route } from "react-router-dom";
import AppShell from "@/components/AppShell";
import DashboardPage from "@/pages/Dashboard";
import LabPage from "@/pages/Lab";
import DatasetsPage from "@/pages/Datasets";
import AcademyPage from "@/pages/Academy";
import AiAssistantPage from "@/pages/AiAssistant";
import ExplainabilityPage from "@/pages/Explainability";
import MitrePage from "@/pages/Mitre";
import CopilotPage from "@/pages/Copilot";
import AiSocMediaPage from "@/pages/AiSocMedia";
import EvidencePage from "@/pages/Evidence";
import VoxCryptPage from "@/pages/VoxCrypt";
import IncidentsPage from "@/pages/Incidents";
import MetricsPage from "@/pages/Metrics";


export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/lab" element={<LabPage />} />
          <Route path="/datasets" element={<DatasetsPage />} />
          <Route path="/academy" element={<AcademyPage />} />
          <Route path="/ai-assistant" element={<AiAssistantPage />} />
          <Route path="/explainability" element={<ExplainabilityPage />} />
          <Route path="/mitre" element={<MitrePage />} />
          <Route path="/copilot" element={<CopilotPage />} />
          <Route path="/ai-soc-media" element={<AiSocMediaPage />} />
          <Route path="/evidence" element={<EvidencePage />} />
          <Route path="/voxcrypt" element={<VoxCryptPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/metrics" element={<MetricsPage />} />
          
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
