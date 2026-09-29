import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { OverallRiskView } from './pages/OverallRiskView';
import { CseAnalysisView } from './pages/CseAnalysisView';
import { AttackPathView } from './pages/AttackPathView';
import { KeyFindingsView } from './pages/KeyFindingsView';
import { PeerComparisonView } from './pages/PeerComparisonView';
import { DrilldownView } from './pages/DrilldownView';
import { ReviewQueueView } from './pages/ReviewQueueView';
import { FeedbackLogView } from './pages/FeedbackLogView';
import { ExportReportsView } from './pages/ExportReportsView';
import { AdminAuditView } from './pages/AdminAuditView';
import { UploadPage } from './UploadPage';
import { NormalizationPage } from './NormalizationPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<OverallRiskView />} />
          <Route path="overall-risk" element={<OverallRiskView />} />
          <Route path="cse-analysis" element={<CseAnalysisView />} />
          <Route path="attack-path" element={<AttackPathView />} />
          <Route path="findings" element={<KeyFindingsView />} />
          <Route path="peer-comparison" element={<PeerComparisonView />} />
          <Route path="drilldown" element={<DrilldownView />} />
          <Route path="reviews" element={<ReviewQueueView />} />
          <Route path="feedback" element={<FeedbackLogView />} />
          <Route path="export" element={<ExportReportsView />} />
          <Route path="admin" element={<AdminAuditView />} />
          <Route path="upload" element={<UploadPage />} />
          <Route path="normalization" element={<NormalizationPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
