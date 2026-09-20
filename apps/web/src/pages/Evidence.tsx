import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { EvidenceResponse, PaginatedResponse } from '../types/api';
import {
  Search,
  Filter,
  ChevronDown,
  Upload,
  Hash,
  CheckCircle,
  AlertCircle,
  Loader2,
  Download,
  Eye,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';

// Missing import - removed duplicate
// import { Eye } from 'lucide-react';

export function Evidence() {
  const [evidenceList, setEvidenceList] = useState<EvidenceResponse[]>([]);
  const [pagination, setPagination] = useState({ page: 1, per_page: 20, total: 0 });
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [verifying, setVerifying] = useState<string | null>(null);
  const [verifyResults, setVerifyResults] = useState<Record<string, boolean>>({});

  useEffect(() => {
    loadEvidence();
  }, [pagination.page, search]);

  const loadEvidence = async () => {
    setLoading(true);
    try {
      const response = await api.get<PaginatedResponse<EvidenceResponse>>('/api/evidence', {
        params: { page: pagination.page, per_page: pagination.per_page, search },
      });
      setEvidenceList(response.data.data);
      setPagination(prev => ({ ...prev, total: response.data.pagination.total }));
    } catch (error) {
      console.error('Failed to load evidence:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const handleVerify = async (evidenceId: string) => {
    setVerifying(evidenceId);
    try {
      const response = await api.post(`/api/evidence/${evidenceId}/verify`);
      setVerifyResults(prev => ({ ...prev, [evidenceId]: response.data.valid }));
    } catch (error) {
      setVerifyResults(prev => ({ ...prev, [evidenceId]: false }));
    } finally {
      setVerifying(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-forensic-100">Evidence Vault</h1>
          <p className="text-forensic-400 mt-1">Manage and verify collected forensic evidence</p>
        </div>
        <Link to="/evidence/upload" className="btn-primary gap-2">
          <Upload className="h-4 w-4" />
          Upload Evidence
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
              placeholder="Search evidence..."
              className="input pl-10"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-5 w-5 text-forensic-500" />
            <select className="input pr-8 appearance-none bg-forensic-800" style={{ width: '180px' }}>
              <option value="">All Investigations</option>
              <option value="verified">Verified</option>
              <option value="unverified">Unverified</option>
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-forensic-500 pointer-events-none" />
          </div>
        </form>
      </div>

      {/* Evidence Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-blue mx-auto" />
          </div>
        ) : evidenceList.length === 0 ? (
          <div className="p-12 text-center">
            <Hash className="h-16 w-16 text-forensic-700 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-forensic-300 mb-2">No evidence found</h3>
            <p className="text-forensic-500 mb-6">Upload evidence files to verify their integrity</p>
            <Link to="/evidence/upload" className="btn-primary gap-2 inline-flex">
              <Upload className="h-4 w-4" />
              Upload Evidence
            </Link>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table className="table" role="table">
                <thead>
                  <tr>
                    <th scope="col">Investigation</th>
                    <th scope="col">Host</th>
                    <th scope="col">Collected</th>
                    <th scope="col">SHA-256</th>
                    <th scope="col">Size</th>
                    <th scope="col">Verification</th>
                    <th scope="col" className="w-32">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {evidenceList.map((item) => {
                    const verified = verifyResults[item.id];
                    const isVerifying = verifying === item.id;
                    return (
                      <tr key={item.id}>
                        <td>
                          <Link to={`/investigations/${item.investigation_id}`} className="font-medium text-forensic-100 hover:text-accent-blue transition-colors truncate max-w-[200px] block">
                            {item.investigation_id.substring(0, 8)}...
                          </Link>
                        </td>
                        <td className="text-sm text-forensic-300">
                          {item.host_identifier || 'Unknown'}
                        </td>
                        <td className="text-sm text-forensic-500">
                          {formatDistanceToNow(new Date(item.collection_time), { addSuffix: true })}
                        </td>
                        <td className="font-mono text-xs text-forensic-400">
                          {item.sha256_hash.substring(0, 16)}...
                        </td>
                        <td className="text-sm text-forensic-500">
                          {(item.size_bytes / 1024 / 1024).toFixed(2)} MB
                        </td>
                        <td>
                          {verified !== undefined ? (
                            <span className={clsx('badge flex items-center gap-1.5', verified ? 'badge-success' : 'badge-danger')}>
                              {verified ? (
                                <>
                                  <CheckCircle className="h-3 w-3" />
                                  Verified
                                </>
                              ) : (
                                <>
                                  <AlertCircle className="h-3 w-3" />
                                  Failed
                                </>
                              )}
                            </span>
                          ) : (
                            <span className="badge badge-neutral">Not verified</span>
                          )}
                        </td>
                        <td>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleVerify(item.id)}
                              disabled={isVerifying || verified !== undefined}
                              className="p-2 rounded-lg text-forensic-400 hover:text-accent-blue hover:bg-forensic-800 transition-colors disabled:opacity-50"
                              title={verified !== undefined ? 'Already verified' : 'Verify integrity'}
                            >
                              {isVerifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <Hash className="h-4 w-4" />}
                            </button>
                            <Link
                              to={`/evidence/${item.id}`}
                              className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors"
                              title="View details"
                            >
                              <Eye className="h-4 w-4" />
                            </Link>
                            {item.storage_path && (
                              <a
                                href={`/api/evidence/${item.id}/download`}
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
                  {pagination.total} evidence items
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