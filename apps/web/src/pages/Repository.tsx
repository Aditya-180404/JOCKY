import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { ToolResponse, PaginatedResponse } from '../types/api';
import {
  Database,
  Plus,
  Search,
  Filter,
  ChevronDown,
  Download,
  Eye,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';

export function Repository() {
  const [tools, setTools] = useState<ToolResponse[]>([]);
  const [pagination, setPagination] = useState({ page: 1, per_page: 20, total: 0 });
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    loadTools();
  }, [pagination.page, search]);

  const loadTools = async () => {
    setLoading(true);
    try {
      const response = await api.get<PaginatedResponse<ToolResponse>>('/api/tools', {
        params: { page: pagination.page, per_page: pagination.per_page, search },
      });
      setTools(response.data.data);
      setPagination(prev => ({ ...prev, total: response.data.pagination.total }));
    } catch (error) {
      console.error('Failed to load tools:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-forensic-100">Tool Repository</h1>
          <p className="text-forensic-400 mt-1">Browse and manage forensic investigation tools</p>
        </div>
        <Link to="/editor" className="btn-primary gap-2">
          <Plus className="h-4 w-4" />
          Create Tool
        </Link>
      </div>

      {/* Search and Filters */}
      <div className="card p-4">
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search tools..."
              className="input pl-10"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-5 w-5 text-forensic-500" />
            <select className="input pr-8 appearance-none bg-forensic-800" style={{ width: '160px' }}>
              <option value="">All Platforms</option>
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-forensic-500 pointer-events-none" />
          </div>
        </form>
      </div>

      {/* Tools Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-blue mx-auto" />
          </div>
        ) : tools.length === 0 ? (
          <div className="p-12 text-center">
            <Database className="h-16 w-16 text-forensic-700 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-forensic-300 mb-2">No tools found</h3>
            <p className="text-forensic-500 mb-6">Get started by creating your first forensic tool</p>
            <Link to="/editor" className="btn-primary gap-2 inline-flex">
              <Plus className="h-4 w-4" />
              Create Tool
            </Link>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table className="table" role="table">
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Latest Version</th>
                    <th scope="col">Platform</th>
                    <th scope="col">Status</th>
                    <th scope="col">Updated</th>
                    <th scope="col" className="w-32">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {tools.map((tool) => {
                    const latestVersion = tool.versions[0];
                    const isPublished = latestVersion?.is_published;
                    return (
                      <tr key={tool.id}>
                        <td>
                          <Link to={`/repository/${tool.id}`} className="font-medium text-forensic-100 hover:text-accent-blue transition-colors">
                            {tool.name}
                          </Link>
                        </td>
                        <td className="font-mono text-sm text-forensic-300">
                          {latestVersion?.version || '—'}
                        </td>
                        <td>
                          {latestVersion && (
                            <span className="badge badge-neutral">
                              {latestVersion.target_platform}/{latestVersion.target_arch}
                            </span>
                          )}
                        </td>
                        <td>
                          <span className={clsx('badge', isPublished ? 'badge-success' : 'badge-warning')}>
                            {isPublished ? 'Published' : 'Draft'}
                          </span>
                        </td>
                        <td className="text-sm text-forensic-500">
                          {latestVersion ? formatDistanceToNow(new Date(latestVersion.updated_at), { addSuffix: true }) : '—'}
                        </td>
                        <td>
                          <div className="flex items-center gap-2">
                            <Link
                              to={`/repository/${tool.id}`}
                              className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors"
                              title="View details"
                            >
                              <Eye className="h-4 w-4" />
                            </Link>
                            {isPublished && latestVersion?.artifact_hash && (
                              <a
                                href={`/api/tools/${tool.id}/download`}
                                className="p-2 rounded-lg text-forensic-400 hover:text-accent-green hover:bg-forensic-800 transition-colors"
                                title="Download"
                              >
                                <Download className="h-4 w-4" />
                              </a>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {pagination.total > pagination.per_page && (
              <div className="p-4 border-t border-forensic-800 flex items-center justify-between">
                <p className="text-sm text-forensic-500">
                  Showing {(pagination.page - 1) * pagination.per_page + 1} to{' '}
                  {Math.min(pagination.page * pagination.per_page, pagination.total)} of{' '}
                  {pagination.total} tools
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPagination(p => ({ ...p, page: p.page - 1 }))}
                    disabled={pagination.page === 1}
                    className="btn-secondary btn-sm"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setPagination(p => ({ ...p, page: p.page + 1 }))}
                    disabled={pagination.page * pagination.per_page >= pagination.total}
                    className="btn-secondary btn-sm"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}