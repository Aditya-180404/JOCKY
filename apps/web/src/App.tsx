import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './contexts/AuthContext';
import { Layout } from './components/Layout';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Dashboard } from './pages/Dashboard';
import { Editor } from './pages/Editor';
import { WebIDE } from './pages/WebIDE';
import { DownloadPage } from './pages/Download';
import { LanguageGuide } from './pages/LanguageGuide';
import { ExamplesPage } from './pages/ExamplesPage';
import { DocsPage } from './pages/Docs';
import { AboutPage } from './pages/About';
import { Repository } from './pages/Repository';
import { ToolDetail } from './pages/ToolDetail';
import { Investigations } from './pages/Investigations';
import { InvestigationDetail } from './pages/InvestigationDetail';
import { Evidence } from './pages/Evidence';
import { EvidenceDetail } from './pages/EvidenceDetail';
import { EvidenceUpload } from './pages/EvidenceUpload';
import { Settings } from './pages/Settings';
import { Admin } from './pages/Admin';
import { Landing } from './pages/Landing';
import { PlaybookGallery } from './pages/PlaybookGallery';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-forensic-950">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-blue"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-forensic-950">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-blue"></div>
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const { user, isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-forensic-950">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-blue"></div>
      </div>
    );
  }

  if (!isAuthenticated || user?.role !== 'ADMIN') {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      {/* Public Website & Web IDE Routes */}
      <Route path="/" element={<Landing />} />
      <Route path="/ide" element={<WebIDE />} />
      <Route path="/playground" element={<WebIDE />} />
      <Route path="/download" element={<DownloadPage />} />
      <Route path="/guide" element={<LanguageGuide />} />
      <Route path="/examples" element={<ExamplesPage />} />
      <Route path="/playbooks" element={<PlaybookGallery />} />
      <Route path="/docs" element={<DocsPage />} />
      <Route path="/about" element={<AboutPage />} />

      {/* Auth Routes */}
      <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
      <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />

      {/* Authenticated Management Platform Routes */}
      <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/editor" element={<WebIDE />} />
        <Route path="/editor/:toolId" element={<Editor />} />
        <Route path="/repository" element={<Repository />} />
        <Route path="/repository/:id" element={<ToolDetail />} />
        <Route path="/investigations" element={<Investigations />} />
        <Route path="/investigations/:id" element={<InvestigationDetail />} />
        <Route path="/evidence" element={<Evidence />} />
        <Route path="/evidence/upload" element={<EvidenceUpload />} />
        <Route path="/evidence/:id" element={<EvidenceDetail />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/admin" element={<AdminRoute><Admin /></AdminRoute>} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}