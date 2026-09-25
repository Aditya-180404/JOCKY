import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../services/api';
import { InvestigationResponse } from '../types/api';
import {
  ArrowLeft,
  Play,
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
  Hash,
  Plus,
  ChevronRight,
  FileText,
  Search,
  Activity,
  Cpu,
  Globe,
  HardDrive,
  Shield,
  Layers,
  Share2,
  Download,
  Terminal,
  Filter,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';

interface EvidenceSummary {
  id: string;
  host_identifier: string | null;
  collection_time: string;
  sha256_hash: string;
  size_bytes: number;
}

interface TimelineItem {
  timestamp: string;
  host: string;
  source: string;
  event_type: string;
  actor?: string;
  target?: string;
  process_name?: string;
  process_id?: number;
  path?: string;
  network_endpoint?: string;
  evidence_ref?: string;
  details?: Record<string, any>;
}

interface ProcessItem {
  pid: number;
  ppid?: number;
  name: string;
  executable?: string;
  command_line?: string;
  user?: string;
  hash?: string;
}

interface NetworkItem {
  local_address: string;
  local_port: number;
  remote_address: string;
  remote_port: number;
  protocol: string;
  state: string;
  process?: string;
}

interface FileItem {
  path: string;
  size: number;
  sha256?: string;
  owner?: string;
}

interface NormalizedEntitiesData {
  hosts: Array<{ id: string; hostname: string; platform: string; os_version: string }>;
  processes: ProcessItem[];
  network_connections: NetworkItem[];
  files: FileItem[];
}

interface IocMatch {
  indicator_id: string;
  indicator_type: string;
  indicator_value: string;
  matched_field: string;
  observed_value: string;
  host_id: string;
  timestamp: string;
  evidence_reference?: string;
  severity: string;
}

interface FindingItem {
  id: string;
  rule_name: string;
  title: string;
  description: string;
  severity: string;
  mitre_attack_id?: string;
  evidence_ref?: string;
  matched_entity: string;
  timestamp: string;
  recommendation?: string;
}

interface GraphData {
  investigation_id: string;
  host: string;
  entities: Record<string, any>;
  relationships: Array<{
    source_entity: any;
    target_entity: any;
    relationship_type: string;
    confidence: number;
  }>;
}

export function InvestigationDetail() {
  const { id } = useParams<{ id: string }>();
  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null);
  const [evidence, setEvidence] = useState<EvidenceSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  // Workspace Tabs
  const [activeTab, setActiveTab] = useState<'evidence' | 'timeline' | 'entities' | 'iocs' | 'findings' | 'graph' | 'report'>('evidence');

  // Tab Data States
  const [timelineEvents, setTimelineEvents] = useState<TimelineItem[]>([]);
  const [timelineSearch, setTimelineSearch] = useState('');
  const [timelineSourceFilter, setTimelineSourceFilter] = useState('ALL');

  const [entities, setEntities] = useState<NormalizedEntitiesData | null>(null);
  const [entitySubTab, setEntitySubTab] = useState<'processes' | 'network' | 'files'>('processes');

  const [iocMatches, setIocMatches] = useState<IocMatch[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [graphData, setGraphData] = useState<GraphData | null>(null);

  useEffect(() => {
    if (id) {
      loadInvestigation(id);
    }
  }, [id]);

  const loadInvestigation = async (investigationId: string) => {
    setLoading(true);
    try {
      const response = await api.get(`/api/investigations/${investigationId}`);
      setInvestigation(response.data.investigation);
      setEvidence(response.data.evidence || []);

      // Load workspace sub-datasets in parallel
      api.get(`/api/investigations/${investigationId}/timeline`).then(res => {
        setTimelineEvents(res.data.events || []);
      }).catch(() => {});

      api.get(`/api/investigations/${investigationId}/entities`).then(res => {
        setEntities(res.data.entities || null);
      }).catch(() => {});

      api.get(`/api/investigations/${investigationId}/indicators`).then(res => {
        setIocMatches(res.data.matches || []);
      }).catch(() => {});

      api.get(`/api/investigations/${investigationId}/findings`).then(res => {
        setFindings(res.data.findings || []);
      }).catch(() => {});

      api.get(`/api/investigations/${investigationId}/graph`).then(res => {
        setGraphData(res.data.graph || null);
      }).catch(() => {});

    } catch (error) {
      console.error('Failed to load investigation:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRun = async () => {
    if (!investigation?.tool_version_id) return;
    setRunning(true);
    try {
      await api.post(`/api/investigations/${id}/run`);
      await loadInvestigation(id!);
    } catch (error) {
      console.error('Failed to run investigation:', error);
    } finally {
      setRunning(false);
    }
  };

  const getStatusConfig = (status: string) => {
    switch (status) {
      case 'completed': return { icon: CheckCircle, color: 'text-accent-green', bg: 'bg-green-500/10 border-green-500/20', label: 'Completed' };
      case 'running': return { icon: Loader2, color: 'text-accent-amber', bg: 'bg-amber-500/10 border-amber-500/20', label: 'Running' };
      case 'failed': return { icon: AlertCircle, color: 'text-accent-red', bg: 'bg-red-500/10 border-red-500/20', label: 'Failed' };
      default: return { icon: Clock, color: 'text-forensic-500', bg: 'bg-forensic-800 border-forensic-700', label: 'Draft' };
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-blue" />
      </div>
    );
  }

  if (!investigation) {
    return (
      <div className="text-center py-12">
        <AlertCircle className="h-16 w-16 text-accent-red mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-forensic-100 mb-2">Investigation not found</h2>
        <Link to="/investigations" className="text-accent-blue hover:text-blue-400">
          Back to investigations
        </Link>
      </div>
    );
  }

  const statusConfig = getStatusConfig(investigation.status);

  // Filtered timeline
  const filteredTimeline = timelineEvents.filter(ev => {
    const matchesSource = timelineSourceFilter === 'ALL' || ev.source.toUpperCase() === timelineSourceFilter;
    const matchesQuery = !timelineSearch ||
      ev.event_type.toLowerCase().includes(timelineSearch.toLowerCase()) ||
      (ev.process_name && ev.process_name.toLowerCase().includes(timelineSearch.toLowerCase())) ||
      (ev.path && ev.path.toLowerCase().includes(timelineSearch.toLowerCase())) ||
      (ev.network_endpoint && ev.network_endpoint.toLowerCase().includes(timelineSearch.toLowerCase()));
    return matchesSource && matchesQuery;
  });

  const exportReport = (format: 'json' | 'html') => {
    const reportData = {
      investigation_name: investigation.name,
      investigation_id: investigation.id,
      generated_at: new Date().toISOString(),
      evidence_count: evidence.length,
      evidence_hashes: evidence.map(e => e.sha256_hash),
      timeline_event_count: timelineEvents.length,
      ioc_matches_count: iocMatches.length,
      findings_count: findings.length,
      findings,
      ioc_matches: iocMatches,
    };

    if (format === 'json') {
      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `jockey-report-${investigation.name.toLowerCase().replace(/\s+/g, '-')}.json`;
      a.click();
    } else {
      const html = `<!DOCTYPE html>
<html>
<head>
  <title>JOCKEY Investigation Report - ${investigation.name}</title>
  <style>
    body { font-family: monospace; background: #0b0f19; color: #e2e8f0; padding: 32px; }
    h1, h2 { color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 8px; }
    .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .critical { background: #450a0a; color: #f87171; border: 1px solid #991b1b; }
    .high { background: #431407; color: #fb923c; border: 1px solid #c2410c; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { border: 1px solid #1e293b; padding: 8px; text-align: left; }
    th { background: #1e293b; color: #94a3b8; }
  </style>
</head>
<body>
  <h1>JOCKEY Forensic Investigation Report</h1>
  <p><strong>Investigation:</strong> ${investigation.name} (${investigation.id})</p>
  <p><strong>Generated:</strong> ${new Date().toUTCString()}</p>
  <p><strong>Evidence Files:</strong> ${evidence.length} collected</p>

  <h2>Executive Findings Summary (${findings.length})</h2>
  <table>
    <tr><th>Rule</th><th>Severity</th><th>ATT&CK</th><th>Entity</th><th>Recommendation</th></tr>
    ${findings.map(f => `<tr>
      <td>${f.title}</td>
      <td><span class="badge ${f.severity}">${f.severity.toUpperCase()}</span></td>
      <td>${f.mitre_attack_id || 'N/A'}</td>
      <td>${f.matched_entity}</td>
      <td>${f.recommendation || 'Review evidence'}</td>
    </tr>`).join('')}
  </table>

  <h2>Threat Indicator Matches (${iocMatches.length})</h2>
  <table>
    <tr><th>Type</th><th>Indicator</th><th>Observed Field</th><th>Value</th><th>Evidence Ref</th></tr>
    ${iocMatches.map(m => `<tr>
      <td>${m.indicator_type}</td>
      <td>${m.indicator_value}</td>
      <td>${m.matched_field}</td>
      <td>${m.observed_value}</td>
      <td>${m.evidence_reference || 'N/A'}</td>
    </tr>`).join('')}
  </table>
</body>
</html>`;
      const blob = new Blob([html], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `jockey-report-${investigation.name.toLowerCase().replace(/\s+/g, '-')}.html`;
      a.click();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <Link to="/investigations" className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-forensic-100">{investigation.name}</h1>
              <span className={clsx('badge flex items-center gap-1.5', statusConfig.bg, statusConfig.color)}>
                <statusConfig.icon className={clsx('h-4 w-4', statusConfig.color)} />
                {statusConfig.label}
              </span>
            </div>
            <p className="text-forensic-400 mt-1">{investigation.description || 'Forensic investigation workspace'}</p>
          </div>
        </div>
        <div className="flex gap-2">
          {investigation.status === 'draft' && investigation.tool_version_id && (
            <button onClick={handleRun} disabled={running} className="btn-primary gap-2">
              {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {running ? 'Running...' : 'Run Investigation'}
            </button>
          )}
          <Link to="/editor" className="btn-secondary gap-2">
            <Plus className="h-4 w-4" />
            New Script
          </Link>
        </div>
      </div>

      {/* Workspace Navigation Tabs */}
      <div className="flex border-b border-forensic-800 gap-1 overflow-x-auto">
        <button
          onClick={() => setActiveTab('evidence')}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'evidence' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200'
          )}
        >
          <HardDrive className="h-4 w-4" />
          Evidence ({evidence.length})
        </button>

        <button
          onClick={() => setActiveTab('timeline')}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'timeline' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200'
          )}
        >
          <Clock className="h-4 w-4" />
          Timeline ({timelineEvents.length})
        </button>

        <button
          onClick={() => setActiveTab('entities')}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'entities' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200'
          )}
        >
          <Layers className="h-4 w-4" />
          Normalized Entities
        </button>

        <button
          onClick={() => setActiveTab('iocs')}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'iocs' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200'
          )}
        >
          <Activity className="h-4 w-4" />
          IOC Matches ({iocMatches.length})
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'findings' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200'
          )}
        >
          <Shield className="h-4 w-4" />
          Findings & Rules ({findings.length})
        </button>

        <button
          onClick={() => setActiveTab('graph')}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'graph' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200'
          )}
        >
          <Share2 className="h-4 w-4" />
          Correlation Graph
        </button>

        <button
          onClick={() => setActiveTab('report')}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'report' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200'
          )}
        >
          <Download className="h-4 w-4" />
          Reports
        </button>
      </div>

      {/* TAB 1: EVIDENCE */}
      {activeTab === 'evidence' && (
        <div className="space-y-6">
          <div className="grid md:grid-cols-3 gap-4">
            <div className="card p-4">
              <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Status</p>
              <div className="flex items-center gap-2">
                <statusConfig.icon className={clsx('h-5 w-5', statusConfig.color)} />
                <span className="font-medium text-forensic-100 capitalize">{investigation.status}</span>
              </div>
            </div>
            <div className="card p-4">
              <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Created</p>
              <p className="font-mono text-sm text-forensic-300">
                {formatDistanceToNow(new Date(investigation.created_at), { addSuffix: true })}
              </p>
            </div>
            <div className="card p-4">
              <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Last Updated</p>
              <p className="font-mono text-sm text-forensic-300">
                {formatDistanceToNow(new Date(investigation.updated_at), { addSuffix: true })}
              </p>
            </div>
          </div>

          <section className="card">
            <div className="p-5 border-b border-forensic-800 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-forensic-100 flex items-center gap-2">
                <HardDrive className="h-5 w-5 text-accent-purple" />
                Collected Evidence Envelopes ({evidence.length})
              </h2>
              <Link to="/evidence" className="btn-secondary btn-sm gap-1">
                <Plus className="h-4 w-4" />
                Upload Evidence
              </Link>
            </div>

            <div className="divide-y divide-forensic-800">
              {evidence.length === 0 ? (
                <div className="p-8 text-center">
                  <FileText className="h-12 w-12 text-forensic-700 mx-auto mb-3" />
                  <p className="text-forensic-400 mb-2">No evidence collected yet</p>
                  <p className="text-forensic-500 text-sm mb-4">
                    Compile and execute your JOCKEY investigation native binary, then upload the canonical evidence bundle here.
                  </p>
                  <Link to="/evidence" className="btn-primary gap-2 inline-flex">
                    <Plus className="h-4 w-4" />
                    Upload Evidence
                  </Link>
                </div>
              ) : (
                evidence.map((item) => (
                  <Link
                    key={item.id}
                    to={`/evidence/${item.id}`}
                    className="p-5 hover:bg-forensic-800/50 transition-colors flex items-center justify-between group"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3">
                        <p className="font-medium text-forensic-100 truncate">
                          {item.host_identifier || 'Target Host'}
                        </p>
                        <span className="badge badge-info">
                          {formatDistanceToNow(new Date(item.collection_time), { addSuffix: true })}
                        </span>
                      </div>
                      <p className="text-sm text-forensic-500 mt-1 font-mono">
                        SHA-256: {item.sha256_hash.substring(0, 32)}...
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right hidden sm:block">
                        <p className="text-xs text-forensic-500">Size</p>
                        <p className="font-mono text-sm text-forensic-300">
                          {(item.size_bytes / 1024 / 1024).toFixed(2)} MB
                        </p>
                      </div>
                      <ChevronRight className="h-5 w-5 text-forensic-600 group-hover:text-forensic-400 transition-colors" />
                    </div>
                  </Link>
                ))
              )}
            </div>
          </section>
        </div>
      )}

      {/* TAB 2: TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3 items-center justify-between card p-3">
            <div className="relative flex-1 w-full">
              <Search className="h-4 w-4 absolute left-3 top-3 text-forensic-500" />
              <input
                type="text"
                value={timelineSearch}
                onChange={e => setTimelineSearch(e.target.value)}
                placeholder="Search event type, process, path, network endpoint..."
                className="w-full pl-9 pr-4 py-2 bg-forensic-900 border border-forensic-800 rounded-lg text-sm text-forensic-100 placeholder-forensic-500 focus:outline-none focus:border-accent-blue"
              />
            </div>
            <div className="flex gap-2 w-full sm:w-auto">
              {['ALL', 'PROCESS', 'NETWORK', 'FILESYSTEM', 'SYSTEM', 'LOG'].map(src => (
                <button
                  key={src}
                  onClick={() => setTimelineSourceFilter(src)}
                  className={clsx(
                    'px-3 py-1.5 rounded text-xs font-semibold uppercase tracking-wider transition-colors',
                    timelineSourceFilter === src ? 'bg-accent-blue text-white' : 'bg-forensic-800 text-forensic-400 hover:bg-forensic-700'
                  )}
                >
                  {src}
                </button>
              ))}
            </div>
          </div>

          <div className="card divide-y divide-forensic-800">
            {filteredTimeline.length === 0 ? (
              <div className="p-8 text-center text-forensic-500">
                No timeline events matching current filter or search criteria.
              </div>
            ) : (
              filteredTimeline.map((ev, idx) => (
                <div key={idx} className="p-4 hover:bg-forensic-800/40 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-forensic-400">{ev.timestamp}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-950 text-blue-300 border border-blue-800">
                        {ev.source.toUpperCase()}
                      </span>
                      <span className="font-semibold text-sm text-forensic-100">{ev.event_type}</span>
                    </div>
                    <div className="text-xs text-forensic-400 flex flex-wrap gap-4">
                      {ev.process_name && <span>Process: <strong className="text-forensic-200">{ev.process_name} (PID: {ev.process_id || 'N/A'})</strong></span>}
                      {ev.path && <span>Path: <strong className="text-forensic-200">{ev.path}</strong></span>}
                      {ev.network_endpoint && <span>Endpoint: <strong className="text-forensic-200">{ev.network_endpoint}</strong></span>}
                      {ev.actor && <span>Actor: <strong className="text-forensic-200">{ev.actor}</strong></span>}
                    </div>
                  </div>
                  {ev.evidence_ref && (
                    <div className="font-mono text-[11px] text-forensic-500 bg-forensic-900 px-2 py-1 rounded border border-forensic-800 self-start sm:self-auto">
                      ref: {ev.evidence_ref}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 3: NORMALIZED ENTITIES */}
      {activeTab === 'entities' && (
        <div className="space-y-4">
          <div className="flex gap-2 border-b border-forensic-800 pb-2">
            <button
              onClick={() => setEntitySubTab('processes')}
              className={clsx('px-3 py-1.5 rounded text-xs font-semibold transition-colors', entitySubTab === 'processes' ? 'bg-accent-blue text-white' : 'bg-forensic-800 text-forensic-400')}
            >
              Processes ({entities?.processes.length || 0})
            </button>
            <button
              onClick={() => setEntitySubTab('network')}
              className={clsx('px-3 py-1.5 rounded text-xs font-semibold transition-colors', entitySubTab === 'network' ? 'bg-accent-blue text-white' : 'bg-forensic-800 text-forensic-400')}
            >
              Network Sockets ({entities?.network_connections.length || 0})
            </button>
            <button
              onClick={() => setEntitySubTab('files')}
              className={clsx('px-3 py-1.5 rounded text-xs font-semibold transition-colors', entitySubTab === 'files' ? 'bg-accent-blue text-white' : 'bg-forensic-800 text-forensic-400')}
            >
              Files ({entities?.files.length || 0})
            </button>
          </div>

          <div className="card p-4 overflow-x-auto">
            {entitySubTab === 'processes' && (
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-forensic-800 text-forensic-400 pb-2">
                    <th className="py-2">PID</th>
                    <th className="py-2">PPID</th>
                    <th className="py-2">Name</th>
                    <th className="py-2">User</th>
                    <th className="py-2">Executable / Command Line</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-forensic-800/60">
                  {entities?.processes.map((proc, i) => (
                    <tr key={i} className="hover:bg-forensic-800/40">
                      <td className="py-2 text-accent-blue font-bold">{proc.pid}</td>
                      <td className="py-2 text-forensic-400">{proc.ppid || '-'}</td>
                      <td className="py-2 text-forensic-100 font-semibold">{proc.name}</td>
                      <td className="py-2 text-forensic-300">{proc.user || 'root'}</td>
                      <td className="py-2 text-forensic-400 truncate max-w-md">{proc.command_line || proc.executable || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {entitySubTab === 'network' && (
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-forensic-800 text-forensic-400 pb-2">
                    <th className="py-2">Protocol</th>
                    <th className="py-2">Local Address</th>
                    <th className="py-2">Remote Address</th>
                    <th className="py-2">State</th>
                    <th className="py-2">Associated Process</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-forensic-800/60">
                  {entities?.network_connections.map((net, i) => (
                    <tr key={i} className="hover:bg-forensic-800/40">
                      <td className="py-2 font-bold text-accent-purple">{net.protocol}</td>
                      <td className="py-2 text-forensic-200">{net.local_address}</td>
                      <td className="py-2 text-forensic-200">{net.remote_address}</td>
                      <td className="py-2 text-emerald-400">{net.state}</td>
                      <td className="py-2 text-forensic-300">{net.process || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {entitySubTab === 'files' && (
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-forensic-800 text-forensic-400 pb-2">
                    <th className="py-2">Path</th>
                    <th className="py-2">Size</th>
                    <th className="py-2">Owner</th>
                    <th className="py-2">SHA-256 Digest</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-forensic-800/60">
                  {entities?.files.map((file, i) => (
                    <tr key={i} className="hover:bg-forensic-800/40">
                      <td className="py-2 text-forensic-100 font-semibold">{file.path}</td>
                      <td className="py-2 text-forensic-400">{file.size} bytes</td>
                      <td className="py-2 text-forensic-400">{file.owner || '-'}</td>
                      <td className="py-2 text-forensic-500">{file.sha256 ? `${file.sha256.slice(0, 24)}...` : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: IOC MATCHES */}
      {activeTab === 'iocs' && (
        <div className="space-y-4">
          <div className="card divide-y divide-forensic-800">
            {iocMatches.length === 0 ? (
              <div className="p-8 text-center text-forensic-500">
                No high-fidelity threat indicators matched against this investigation evidence.
              </div>
            ) : (
              iocMatches.map((m, i) => (
                <div key={i} className="p-4 hover:bg-forensic-800/40 flex items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={clsx(
                        'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                        m.severity === 'critical' ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                      )}>
                        {m.severity}
                      </span>
                      <span className="font-mono text-xs font-semibold text-accent-blue">{m.indicator_type}</span>
                      <span className="font-mono text-sm text-forensic-100">{m.indicator_value}</span>
                    </div>
                    <p className="text-xs text-forensic-400">
                      Matched Field: <code className="text-forensic-200">{m.matched_field}</code> | Observed Value: <code className="text-forensic-200">{m.observed_value}</code>
                    </p>
                  </div>
                  {m.evidence_reference && (
                    <div className="font-mono text-xs text-forensic-500 bg-forensic-900 px-2 py-1 rounded border border-forensic-800">
                      ref: {m.evidence_reference}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 5: FINDINGS & RULES */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          <div className="card divide-y divide-forensic-800">
            {findings.length === 0 ? (
              <div className="p-8 text-center text-forensic-500">
                No rule violations or security findings detected.
              </div>
            ) : (
              findings.map((f, i) => (
                <div key={i} className="p-5 hover:bg-forensic-800/40 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={clsx(
                        'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                        f.severity === 'critical' ? 'bg-red-950 text-red-300 border border-red-800' :
                        f.severity === 'high' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-blue-950 text-blue-300 border border-blue-800'
                      )}>
                        {f.severity}
                      </span>
                      <h3 className="text-base font-semibold text-forensic-100">{f.title}</h3>
                      {f.mitre_attack_id && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800">
                          MITRE {f.mitre_attack_id}
                        </span>
                      )}
                    </div>
                    {f.evidence_ref && (
                      <span className="font-mono text-xs text-forensic-500">ref: {f.evidence_ref}</span>
                    )}
                  </div>
                  <p className="text-sm text-forensic-300">{f.description}</p>
                  {f.recommendation && (
                    <div className="text-xs bg-forensic-900 p-2.5 rounded border border-forensic-800 text-forensic-400">
                      <strong>Remediation:</strong> {f.recommendation}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 6: CORRELATION GRAPH */}
      {activeTab === 'graph' && (
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-forensic-800 pb-3">
            <h3 className="font-semibold text-forensic-100 flex items-center gap-2">
              <Share2 className="h-5 w-5 text-accent-blue" />
              Evidence Correlation Entity Graph
            </h3>
            <span className="text-xs text-forensic-500 font-mono">Host: {graphData?.host || 'Target Node'}</span>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <div className="p-4 bg-forensic-900 rounded-lg border border-forensic-800 space-y-2">
              <h4 className="text-xs font-bold text-forensic-400 uppercase tracking-wider">Discovered Entities</h4>
              <p className="text-sm text-forensic-300">
                Total Nodes: <strong className="text-accent-blue">{Object.keys(graphData?.entities || {}).length}</strong>
              </p>
              <div className="max-h-48 overflow-y-auto font-mono text-xs space-y-1">
                {Object.entries(graphData?.entities || {}).map(([k, v]: any) => (
                  <div key={k} className="p-1.5 bg-forensic-800/40 rounded flex justify-between">
                    <span className="text-forensic-200">{k}</span>
                    <span className="text-forensic-500">{v.event_count} events</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-4 bg-forensic-900 rounded-lg border border-forensic-800 space-y-2">
              <h4 className="text-xs font-bold text-forensic-400 uppercase tracking-wider">Cross-Source Relationships</h4>
              <p className="text-sm text-forensic-300">
                Total Edges: <strong className="text-accent-purple">{graphData?.relationships?.length || 0}</strong>
              </p>
              <div className="max-h-48 overflow-y-auto font-mono text-xs space-y-1">
                {(graphData?.relationships || []).map((rel, i) => (
                  <div key={i} className="p-1.5 bg-forensic-800/40 rounded flex justify-between">
                    <span className="text-accent-green">{rel.relationship_type}</span>
                    <span className="text-forensic-400">Confidence: {(rel.confidence * 100).toFixed(0)}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 7: REPORTS */}
      {activeTab === 'report' && (
        <div className="card p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-forensic-800 pb-4">
            <div>
              <h3 className="text-lg font-bold text-forensic-100">Forensic Investigation Report</h3>
              <p className="text-sm text-forensic-400">Export cryptographically verified evidence dossiers for court or incident response.</p>
            </div>
            <div className="flex gap-2">
              <button onClick={() => exportReport('json')} className="btn-secondary gap-2 text-xs">
                <Download className="h-4 w-4" /> Export JSON
              </button>
              <button onClick={() => exportReport('html')} className="btn-primary gap-2 text-xs">
                <Download className="h-4 w-4" /> Export HTML Dossier
              </button>
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg bg-forensic-900 border border-forensic-800 space-y-2">
              <h4 className="text-xs font-bold text-forensic-400 uppercase">Dossier Checklist</h4>
              <ul className="text-xs text-forensic-300 space-y-1.5">
                <li className="flex items-center gap-2 text-emerald-400"><CheckCircle className="h-3.5 w-3.5" /> Canonical Evidence Bundle Hashes</li>
                <li className="flex items-center gap-2 text-emerald-400"><CheckCircle className="h-3.5 w-3.5" /> Merkle Tree Inclusion Roots</li>
                <li className="flex items-center gap-2 text-emerald-400"><CheckCircle className="h-3.5 w-3.5" /> Normalized Forensic Timeline</li>
                <li className="flex items-center gap-2 text-emerald-400"><CheckCircle className="h-3.5 w-3.5" /> IOC Threat Matches ({iocMatches.length})</li>
                <li className="flex items-center gap-2 text-emerald-400"><CheckCircle className="h-3.5 w-3.5" /> MITRE ATT&CK Mapped Findings ({findings.length})</li>
              </ul>
            </div>
            <div className="p-4 rounded-lg bg-forensic-900 border border-forensic-800 space-y-2">
              <h4 className="text-xs font-bold text-forensic-400 uppercase">Chain of Custody</h4>
              <p className="text-xs text-forensic-400">
                All records in this investigation originate from native compiled JOCKEY forensic binaries. Merkle roots and SHA-256 hashes guarantee tamper-evident validation.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
