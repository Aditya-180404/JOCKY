import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../services/api';
import { ToolResponse, ToolVersionResponse } from '../types/api';
import {
  ArrowLeft,
  Download,
  Hash,
  Settings,
  CheckCircle,
  AlertCircle,
  Copy,
  Plus,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';

export function ToolDetail() {
  const { id } = useParams<{ id: string }>();
  const [tool, setTool] = useState<ToolResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      loadTool(id);
    }
  }, [id]);

  const loadTool = async (toolId: string) => {
    setLoading(true);
    try {
      const response = await api.get(`/api/tools/${toolId}`);
      setTool(response.data);
    } catch (error) {
      console.error('Failed to load tool:', error);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-blue" />
      </div>
    );
  }

  if (!tool) {
    return (
      <div className="text-center py-12">
        <AlertCircle className="h-16 w-16 text-accent-red mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-forensic-100 mb-2">Tool not found</h2>
        <Link to="/repository" className="text-accent-blue hover:text-blue-400">
          Back to repository
        </Link>
      </div>
    );
  }

  const latestVersion = tool.versions[0];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <Link to="/repository" className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-forensic-100">{tool.name}</h1>
            <p className="text-forensic-400 mt-1">{tool.description || 'No description'}</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Link to={`/editor/${tool.id}`} className="btn-secondary gap-2">
            <Settings className="h-4 w-4" />
            Edit
          </Link>
        </div>
      </div>

      {/* Version Tabs */}
      <div className="card">
        <div className="border-b border-forensic-800">
          <nav className="flex gap-1 p-1" role="tablist">
            <button
              role="tab"
              aria-selected={true}
              className="px-4 py-2 rounded-lg text-sm font-medium text-forensic-100 bg-forensic-800"
            >
              Versions
            </button>
            <button
              role="tab"
              aria-selected={false}
              className="px-4 py-2 rounded-lg text-sm font-medium text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800/50"
            >
              Builds
            </button>
            <button
              role="tab"
              aria-selected={false}
              className="px-4 py-2 rounded-lg text-sm font-medium text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800/50"
            >
              Capabilities
            </button>
          </nav>
        </div>

        {/* Versions Table */}
        <div className="p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-forensic-100">Versions ({tool.versions.length})</h2>
            <Link to={`/editor/${tool.id}`} className="btn-primary btn-sm gap-1">
              <Plus className="h-4 w-4" />
              New Version
            </Link>
          </div>

          <div className="table-container">
            <table className="table" role="table">
              <thead>
                <tr>
                  <th scope="col">Version</th>
                  <th scope="col">Platform</th>
                  <th scope="col">Compiler</th>
                  <th scope="col">Status</th>
                  <th scope="col">Artifact</th>
                  <th scope="col">Created</th>
                  <th scope="col" className="w-40">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tool.versions.map((version) => (
                  <tr key={version.id}>
                    <td>
                      <span className="font-mono font-medium text-forensic-100">{version.version}</span>
                    </td>
                    <td>
                      <span className="badge badge-neutral">
                        {version.target_platform}/{version.target_arch}
                      </span>
                    </td>
                    <td className="text-sm text-forensic-400 font-mono">{version.compiler_version}</td>
                    <td>
                      <span className={clsx('badge', version.is_published ? 'badge-success' : 'badge-warning')}>
                        {version.is_published ? 'Published' : 'Draft'}
                      </span>
                    </td>
                    <td>
                      {version.artifact_hash ? (
                        <div className="flex items-center gap-2">
                          <Hash className="h-4 w-4 text-forensic-500" />
                          <span className="font-mono text-xs text-forensic-300">
                            {version.artifact_hash.substring(0, 16)}...
                          </span>
                        </div>
                      ) : (
                        <span className="text-forensic-500 text-sm">Not built</span>
                      )}
                    </td>
                    <td className="text-sm text-forensic-500">
                      {formatDistanceToNow(new Date(version.created_at), { addSuffix: true })}
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        {version.is_published && version.artifact_hash && (
                          <a
                            href={`/api/tools/${tool.id}/download`}
                            className="p-2 rounded-lg text-forensic-400 hover:text-accent-green hover:bg-forensic-800 transition-colors"
                            title="Download artifact"
                          >
                            <Download className="h-4 w-4" />
                          </a>
                        )}
                        <button
                          onClick={() => copyToClipboard(version.id, 'version-id')}
                          className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors"
                          title={copied === 'version-id' ? 'Copied!' : 'Copy version ID'}
                        >
                          {copied === 'version-id' ? (
                            <CheckCircle className="h-4 w-4 text-accent-green" />
                          ) : (
                            <Copy className="h-4 w-4" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Latest Version Details */}
        {latestVersion && (
          <div className="border-t border-forensic-800 p-4">
            <h3 className="text-lg font-semibold text-forensic-100 mb-4">Latest Version Details</h3>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-4 bg-forensic-800/50 rounded-lg">
                <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Source Hash</p>
                <p className="font-mono text-sm text-forensic-300 truncate">{latestVersion.source_hash}</p>
              </div>
              <div className="p-4 bg-forensic-800/50 rounded-lg">
                <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Compiler</p>
                <p className="font-mono text-sm text-forensic-300">{latestVersion.compiler_version}</p>
              </div>
              <div className="p-4 bg-forensic-800/50 rounded-lg">
                <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Compiler Hash</p>
                <p className="font-mono text-sm text-forensic-300 truncate">{latestVersion.compiler_hash}</p>
              </div>
              <div className="p-4 bg-forensic-800/50 rounded-lg">
                <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Built</p>
                <p className="text-sm text-forensic-300">
                  {latestVersion.published_at
                    ? formatDistanceToNow(new Date(latestVersion.published_at), { addSuffix: true })
                    : 'Not published'}
                </p>
              </div>
            </div>

            {/* Capabilities */}
            {latestVersion.capabilities.length > 0 && (
              <div className="mt-6">
                <h4 className="text-sm font-medium text-forensic-300 mb-3">Required Capabilities</h4>
                <div className="flex flex-wrap gap-2">
                  {latestVersion.capabilities.map((cap) => (
                    <span key={cap} className="badge badge-info">{cap}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}