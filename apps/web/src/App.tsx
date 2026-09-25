import { Navigate, Route, Routes } from 'react-router-dom';
import { DownloadPage } from './pages/Download';
import { DocsPage } from './pages/Docs';
import { ExamplesPage } from './pages/ExamplesPage';
import { Landing } from './pages/Landing';
import { LanguageGuide } from './pages/LanguageGuide';
import { PlaybookGallery } from './pages/PlaybookGallery';
import { WebIDE } from './pages/WebIDE';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/ide" element={<WebIDE />} />
      <Route path="/download" element={<DownloadPage />} />
      <Route path="/guide" element={<LanguageGuide />} />
      <Route path="/examples" element={<ExamplesPage />} />
      <Route path="/playbooks" element={<PlaybookGallery />} />
      <Route path="/docs" element={<DocsPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
