import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { ToolResponse, InvestigationResponse } from '../types/api';
import {
  Terminal,
  Database,
  FileText,
  Search,
  Plus,
  Activity,
  ChevronRight,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';

interface Stats {
  tools: number;
  investigations: number;
  evidence: number;
  builds: number | null;
}

export function Dashboard() {
  const [stats, setStats] = useState<Stats>({ tools: 0, investigations: 0, evidence: 0, builds: 0 });
  const [recentTools, setRecentTools] = useState<ToolResponse[]>([]);
  const [recentInvestigations, setRecentInvestigations] = useState<InvestigationResponse[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      const [toolsRes, investigationsRes, evidenceRes] = await Promise.all([
        api.get('/api/tools', { params: { per_page: 5 } }),
        api.get('/api/investigations', { params: { per_page: 5 } }),
        api.get('/api/evidence', { params: { per_page: 5 } }),
      ]);

      setStats({
        tools: toolsRes.data.pagination.total,
        investigations: investigationsRes.data.pagination.total,
        evidence: evidenceRes.data.pagination.total,
        builds: null,
      });
      setRecentTools(toolsRes.data.data);
      setRecentInvestigations(investigationsRes.data.data);
    } catch (error) {
      console.error('Failed to load dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  const statCards = [
    { name: 'Tools', value: stats.tools, icon: Database, color: 'text-accent-blue', href: '/repository' },
    { name: 'Investigations', value: stats.investigations, icon: FileText, color: 'text-accent-green', href: '/investigations' },
    { name: 'Evidence', value: stats.evidence, icon: Search, color: 'text-accent-purple', href: '/evidence' },
    { name: 'Builds', value: stats.builds, icon: Activity, color: 'text-accent-amber', href: '/repository' },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-blue" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-forensic-100">Dashboard</h1>
          <p className="text-forensic-400 mt-1">Overview of your forensic tools and investigations</p>
        </div>
        <div className="flex gap-3">
          <Link to="/editor" className="btn-primary gap-2">
            <Plus className="h-4 w-4" />
            New Investigation
          </Link>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((stat) => (
          <Link key={stat.name} to={stat.href} className="card-hover p-5 group">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-forensic-400 text-sm font-medium">{stat.name}</p>
                <p className="text-3xl font-bold text-forensic-100 mt-1">{stat.value ?? '—'}</p>
              </div>
              <div className={clsx('h-12 w-12 rounded-xl flex items-center justify-center', stat.color, 'bg-opacity-10 group-hover:bg-opacity-20 transition-all')}>
                <stat.icon className="h-7 w-7" />
              </div>
            </div>
            <div className="mt-4 flex items-center gap-1 text-forensic-500 text-xs group-hover:text-accent-blue transition-colors">
              <ChevronRight className="h-4 w-4" />
              <span>{stat.value === null ? 'Not available from API' : 'View all'}</span>
            </div>
          </Link>
        ))}
      </div>

      {/* Recent Activity */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Recent Tools */}
        <section className="card">
          <div className="p-5 border-b border-forensic-800 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-forensic-100 flex items-center gap-2">
              <Terminal className="h-5 w-5 text-accent-blue" />
              Recent Tools
            </h2>
            <Link to="/repository" className="text-sm text-accent-blue hover:text-blue-400 flex items-center gap-1">
              View all <ChevronRight className="h-4 w-4" />
            </Link>
          </div>
          <div className="divide-y divide-forensic-800">
            {recentTools.length === 0 ? (
              <div className="p-8 text-center">
                <Terminal className="h-12 w-12 text-forensic-700 mx-auto mb-3" />
                <p className="text-forensic-400">No tools yet</p>
                <Link to="/editor" className="mt-3 inline-flex items-center gap-1 text-accent-blue hover:text-blue-400 text-sm font-medium">
                  Create your first tool <ChevronRight className="h-4 w-4" />
                </Link>
              </div>
            ) : (
              recentTools.map((tool) => (
                <Link key={tool.id} to={`/repository/${tool.id}`} className="p-5 hover:bg-forensic-800/50 transition-colors flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-forensic-100 truncate">{tool.name}</p>
                    <p className="text-sm text-forensic-500 mt-0.5">{tool.versions.length} version{tool.versions.length !== 1 ? 's' : ''}</p>
                  </div>
                  <ChevronRight className="h-5 w-5 text-forensic-600" />
                </Link>
              ))
            )}
          </div>
        </section>

        {/* Recent Investigations */}
        <section className="card">
          <div className="p-5 border-b border-forensic-800 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-forensic-100 flex items-center gap-2">
              <FileText className="h-5 w-5 text-accent-green" />
              Recent Investigations
            </h2>
            <Link to="/investigations" className="text-sm text-accent-blue hover:text-blue-400 flex items-center gap-1">
              View all <ChevronRight className="h-4 w-4" />
            </Link>
          </div>
          <div className="divide-y divide-forensic-800">
            {recentInvestigations.length === 0 ? (
              <div className="p-8 text-center">
                <FileText className="h-12 w-12 text-forensic-700 mx-auto mb-3" />
                <p className="text-forensic-400">No investigations yet</p>
                <Link to="/investigations" className="mt-3 inline-flex items-center gap-1 text-accent-blue hover:text-blue-400 text-sm font-medium">
                  Create investigation <ChevronRight className="h-4 w-4" />
                </Link>
              </div>
            ) : (
              recentInvestigations.map((inv) => (
                <Link key={inv.id} to={`/investigations/${inv.id}`} className="p-5 hover:bg-forensic-800/50 transition-colors flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-forensic-100 truncate">{inv.name}</p>
                      <span className={clsx('badge', inv.status === 'completed' && 'badge-success', inv.status === 'running' && 'badge-warning', inv.status === 'failed' && 'badge-danger', inv.status === 'draft' && 'badge-neutral')}>
                        {inv.status}
                      </span>
                    </div>
                    <p className="text-sm text-forensic-500 mt-0.5">
                      Updated {formatDistanceToNow(new Date(inv.updated_at), { addSuffix: true })}
                    </p>
                  </div>
                  <ChevronRight className="h-5 w-5 text-forensic-600" />
                </Link>
              ))
            )}
          </div>
        </section>
      </div>

      {/* Quick Actions */}
      <section className="card p-6">
        <h2 className="text-lg font-semibold text-forensic-100 mb-4 flex items-center gap-2">
          <Activity className="h-5 w-5 text-accent-amber" />
          Quick Actions
        </h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <Link to="/editor" className="card-hover p-5 text-center group">
            <Terminal className="h-10 w-10 text-accent-blue mx-auto mb-3 group-hover:scale-110 transition-transform" />
            <h3 className="font-medium text-forensic-100">New Investigation</h3>
            <p className="text-sm text-forensic-400 mt-1">Write and compile forensic tools</p>
          </Link>
          <Link to="/repository" className="card-hover p-5 text-center group">
            <Database className="h-10 w-10 text-accent-green mx-auto mb-3 group-hover:scale-110 transition-transform" />
            <h3 className="font-medium text-forensic-100">Browse Repository</h3>
            <p className="text-sm text-forensic-400 mt-1">View published tools and versions</p>
          </Link>
          <Link to="/investigations" className="card-hover p-5 text-center group">
            <FileText className="h-10 w-10 text-accent-purple mx-auto mb-3 group-hover:scale-110 transition-transform" />
            <h3 className="font-medium text-forensic-100">Manage Investigations</h3>
            <p className="text-sm text-forensic-400 mt-1">Track investigation progress</p>
          </Link>
          <Link to="/evidence" className="card-hover p-5 text-center group">
            <Search className="h-10 w-10 text-accent-amber mx-auto mb-3 group-hover:scale-110 transition-transform" />
            <h3 className="font-medium text-forensic-100">Evidence Vault</h3>
            <p className="text-sm text-forensic-400 mt-1">Verify and manage collected evidence</p>
          </Link>
        </div>
      </section>
    </div>
  );
}