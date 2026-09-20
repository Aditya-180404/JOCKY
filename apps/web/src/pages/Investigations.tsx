import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { InvestigationResponse, PaginatedResponse } from '../types/api';
import {
  FileText,
  Plus,
  Search,
  Filter,
  ChevronDown,
  Play,
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';

export function Investigations() {
  const [investigations, setInvestigations] = useState<InvestigationResponse[]>([]);
  const [pagination, setPagination] = useState({ page: 1, per_page: 20, total: 0 });
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    loadInvestigations();
  }, [pagination.page, search]);

  const loadInvestigations = async () => {
    setLoading(true);
    try {
      const response = await api.get<PaginatedResponse<InvestigationResponse>>('/api/investigations', {
        params: { page: pagination.page, per_page: pagination.per_page, search },
      });
      setInvestigations(response.data.data);
      setPagination(prev => ({ ...prev, total: response.data.pagination.total }));
    } catch (error) {
      console.error('Failed to load investigations:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-accent-green" />;
      case 'running': return <Loader2 className="h-4 w-4 text-accent-amber animate-spin" />;
      case 'failed': return <AlertCircle className="h-4 w-4 text-accent-red" />;
      default: return <Clock className="h-4 w-4 text-forensic-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-forensic-100">Investigations</h1>
          <p className="text-forensic-400 mt-1">Manage and run forensic investigations</p>
        </div>
        <Link to="/editor" className="btn-primary gap-2">
          <Plus className="h-4 w-4" />
          New Investigation
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
              placeholder="Search investigations..."
              className="input pl-10"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-5 w-5 text-forensic-500" />
            <select className="input pr-8 appearance-none bg-forensic-800" style={{ width: '160px' }}>
              <option value="">All Status</option>
              <option value="draft">Draft</option>
              <option value="running">Running</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-forensic-500 pointer-events-none" />
          </div>
        </form>
      </div>

      {/* Investigations Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-blue mx-auto" />
          </div>
        ) : investigations.length === 0 ? (
          <div className="p-12 text-center">
            <FileText className="h-16 w-16 text-forensic-700 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-forensic-300 mb-2">No investigations yet</h3>
            <p className="text-forensic-500 mb-6">Create your first investigation to get started</p>
            <Link to="/editor" className="btn-primary gap-2 inline-flex">
              <Plus className="h-4 w-4" />
              Create Investigation
            </Link>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table className="table" role="table">
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Tool</th>
                    <th scope="col">Status</th>
                    <th scope="col">Created</th>
                    <th scope="col">Updated</th>
                    <th scope="col" className="w-32">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {investigations.map((inv) => (
                    <tr key={inv.id}>
                      <td>
                        <Link to={`/investigations/${inv.id}`} className="font-medium text-forensic-100 hover:text-accent-blue transition-colors">
                          {inv.name}
                        </Link>
                      </td>
                      <td className="text-sm text-forensic-400">
                        {inv.tool_version_id ? 'Linked' : '—'}
                      </td>
                      <td>
                        <span className={clsx('badge flex items-center gap-1.5',
                          inv.status === 'completed' && 'badge-success',
                          inv.status === 'running' && 'badge-warning',
                          inv.status === 'failed' && 'badge-danger',
                          inv.status === 'draft' && 'badge-neutral'
                        )}>
                          {getStatusIcon(inv.status)}
                          {inv.status.charAt(0).toUpperCase() + inv.status.slice(1)}
                        </span>
                      </td>
                      <td className="text-sm text-forensic-500">
                        {formatDistanceToNow(new Date(inv.created_at), { addSuffix: true })}
                      </td>
                      <td className="text-sm text-forensic-500">
                        {formatDistanceToNow(new Date(inv.updated_at), { addSuffix: true })}
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <Link
                            to={`/investigations/${inv.id}`}
                            className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors"
                            title="View details"
                          >
                            <Eye className="h-4 w-4" />
                          </Link>
                          {inv.status === 'draft' && inv.tool_version_id && (
                            <button
                              className="btn-primary btn-sm gap-1"
                              title="Run investigation"
                            >
                              <Play className="h-4 w-4" />
                              Run
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {pagination.total > pagination.per_page && (
              <div className="p-4 border-t border-forensic-800 flex items-center justify-between">
                <p className="text-sm text-forensic-500">
                  Showing {(pagination.page - 1) * pagination.per_page + 1} to{' '}
                  {Math.min(pagination.page * pagination.per_page, pagination.total)} of{' '}
                  {pagination.total} investigations
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

// Missing import
import { Eye } from 'lucide-react';