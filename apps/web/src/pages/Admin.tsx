import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { AuditLogResponse, PaginatedResponse } from '../types/api';
import {
  Users,
  Activity,
  Search,
  Filter,
  Eye,
  Shield,
  AlertCircle,
  CheckCircle,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';

export function Admin() {
  const [auditLogs, setAuditLogs] = useState<AuditLogResponse[]>([]);
  const [pagination, setPagination] = useState({ page: 1, per_page: 50, total: 0 });
  const [actionFilter, setActionFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [activeTab, setActiveTab] = useState<'audit' | 'users'>('audit');

  useEffect(() => {
    loadData();
  }, [pagination.page, actionFilter, userFilter, activeTab]);

  const loadData = async () => {
    try {
      if (activeTab === 'audit') {
        const response = await api.get<PaginatedResponse<AuditLogResponse>>('/api/audit-logs', {
          params: { page: pagination.page, per_page: pagination.per_page, action: actionFilter, user_id: userFilter },
        });
        setAuditLogs(response.data.data);
        setPagination(prev => ({ ...prev, total: response.data.pagination.total }));
      }
    } catch (error) {
      console.error('Failed to load admin data:', error);
    }
  };

  const getActionColor = (action: string) => {
    if (action.includes('CREATE') || action.includes('PUBLISH')) return 'text-accent-green';
    if (action.includes('DELETE') || action.includes('FAIL')) return 'text-accent-red';
    if (action.includes('LOGIN') || action.includes('AUTH')) return 'text-accent-blue';
    if (action.includes('BUILD') || action.includes('COMPILE')) return 'text-accent-amber';
    return 'text-forensic-400';
  };

  const getResultIcon = (result: string) => {
    return result === 'success' ? (
      <CheckCircle className="h-4 w-4 text-accent-green" />
    ) : (
      <AlertCircle className="h-4 w-4 text-accent-red" />
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-forensic-100">Administration</h1>
          <p className="text-forensic-400 mt-1">System administration and audit logging</p>
        </div>
        <Shield className="h-8 w-8 text-accent-purple" />
      </div>

      {/* Tabs */}
      <div className="card">
        <div className="border-b border-forensic-800">
          <nav className="flex gap-1 p-1" role="tablist">
            <button
              role="tab"
              aria-selected={activeTab === 'audit'}
              onClick={() => setActiveTab('audit')}
              className={clsx(
                'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                activeTab === 'audit'
                  ? 'bg-forensic-800 text-forensic-100'
                  : 'text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800/50'
              )}
            >
              <Activity className="h-4 w-4 inline mr-1" />
              Audit Logs
            </button>
            <button
              role="tab"
              aria-selected={activeTab === 'users'}
              onClick={() => setActiveTab('users')}
              className={clsx(
                'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                activeTab === 'users'
                  ? 'bg-forensic-800 text-forensic-100'
                  : 'text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800/50'
              )}
            >
              <Users className="h-4 w-4 inline mr-1" />
              Users
            </button>
          </nav>
        </div>

        {/* Audit Logs Tab */}
        {activeTab === 'audit' && (
          <div className="p-4">
            {/* Filters */}
            <div className="flex flex-col sm:flex-row gap-4 mb-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                <input
                  type="search"
                  value={actionFilter}
                  onChange={(e) => { setActionFilter(e.target.value); setPagination(p => ({ ...p, page: 1 })); }}
                  placeholder="Filter by action..."
                  className="input pl-10"
                />
              </div>
              <div className="relative flex-1">
                <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                <input
                  type="search"
                  value={userFilter}
                  onChange={(e) => { setUserFilter(e.target.value); setPagination(p => ({ ...p, page: 1 })); }}
                  placeholder="Filter by user ID..."
                  className="input pl-10"
                />
              </div>
            </div>

            {/* Audit Logs Table */}
            <div className="table-container">
              <table className="table" role="table">
                <thead>
                  <tr>
                    <th scope="col">Time</th>
                    <th scope="col">Action</th>
                    <th scope="col">Resource</th>
                    <th scope="col">User</th>
                    <th scope="col">Result</th>
                    <th scope="col">IP Address</th>
                    <th scope="col">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => (
                    <tr key={log.id}>
                      <td className="text-sm text-forensic-500 font-mono">
                        {formatDistanceToNow(new Date(log.created_at), { addSuffix: true })}
                      </td>
                      <td>
                        <span className={clsx('badge', getActionColor(log.action))}>
                          {log.action.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="text-sm text-forensic-400">
                        {log.resource_type || '—'}{log.resource_id && ` (${log.resource_id.substring(0, 8)}...)`}
                      </td>
                      <td className="text-sm text-forensic-300 font-mono">
                        {log.user_id ? log.user_id.substring(0, 8) + '...' : 'System'}
                      </td>
                      <td>
                        <span className="badge flex items-center gap-1.5">
                          {getResultIcon(log.result)}
                          {log.result}
                        </span>
                      </td>
                      <td className="text-sm text-forensic-500 font-mono">
                        {log.ip_address || '—'}
                      </td>
                      <td>
                        {log.metadata && Object.keys(log.metadata).length > 0 && (
                          <button className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors">
                            <Eye className="h-4 w-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {pagination.total > pagination.per_page && (
              <div className="mt-4 p-4 border-t border-forensic-800 flex items-center justify-between">
                <p className="text-sm text-forensic-500">
                  Showing {(pagination.page - 1) * pagination.per_page + 1} to{' '}
                  {Math.min(pagination.page * pagination.per_page, pagination.total)} of{' '}
                  {pagination.total} log entries
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
          </div>
        )}

        {/* Users Tab */}
        {activeTab === 'users' && (
          <div className="p-4">
            <div className="text-center py-12">
              <Users className="h-16 w-16 text-forensic-700 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-forensic-300 mb-2">User Management</h3>
              <p className="text-forensic-500 mb-6">
                User management features will be available in a future release.
                Currently, users are managed through the registration flow.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}