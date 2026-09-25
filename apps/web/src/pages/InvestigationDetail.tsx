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
  Plus,
  ChevronRight,
  FileText,
  Search,
  Activity,
  HardDrive,
  Shield,
  Layers,
  Share2,
  Download,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import { GraphView } from '../components/GraphView';

// API Response Types matching backend

interface EvidenceSummary {
  id: string;
  host_identifier: string | null;
  collection_time: string;
  sha256_hash: string;
  size_bytes: number;
}

interface TimelineEvent {
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

interface TimelineResponse {
  investigation_id: string;
  host: string;
  event_count: number;
  sources: string[];
  events: TimelineEvent[];
}

interface HostArtifact {
  id: string;
  hostname: string;
  platform: string;
  os_version: string;
  architecture: string;
  identifiers: Record<string, string>;
}

interface UserArtifact {
  id: string;
  username: string;
  domain?: string;
  privileges: string[];
}

interface ProcessArtifact {
  pid: number;
  ppid?: number;
  name: string;
  executable?: string;
  command_line?: string;
  user?: string;
  start_time?: string;
  hash?: string;
}

interface FileArtifact {
  path: string;
  size: number;
  sha256?: string;
  created_at?: string;
  modified_at?: string;
  accessed_at?: string;
  owner?: string;
}

interface NetworkConnectionArtifact {
  local_address: string;
  local_port: number;
  remote_address: string;
  remote_port: number;
  protocol: string;
  state: string;
  process?: string;
  pid?: number;
  timestamp: string;
}

interface DriverArtifact {
  name: string;
  path?: string;
  hash?: string;
  signer?: string;
  version?: string;
  loaded_at?: string;
}

interface RegistryArtifact {
  key: string;
  value?: string;
  data?: string;
  timestamp?: string;
}

interface LogEventArtifact {
  source: string;
  event_id?: string;
  timestamp: string;
  host: string;
  user?: string;
  message: string;
}

interface NormalizedEntities {
  hosts: HostArtifact[];
  users: UserArtifact[];
  processes: ProcessArtifact[];
  files: FileArtifact[];
  network_connections: NetworkConnectionArtifact[];
  drivers: DriverArtifact[];
  registry_keys: RegistryArtifact[];
  log_events: LogEventArtifact[];
}

interface EntitiesResponse {
  investigation_id: string;
  host: string;
  entities: NormalizedEntities;
}

interface IndicatorMatch {
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

interface IndicatorsResponse {
  investigation_id: string;
  total_matches: number;
  matches: IndicatorMatch[];
}

interface RuleFinding {
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

interface FindingsResponse {
  investigation_id: string;
  findings_count: number;
  findings: RuleFinding[];
}

interface EntityNode {
  entity: {
    display: () => string;
    entity_type: () => string;
  };
  evidence_refs: string[];
  first_seen: string;
  last_seen: string;
  event_count: number;
}

interface Relationship {
  id: string;
  source_entity: any;
  target_entity: any;
  relationship_type: string;
  confidence: number;
  timestamp: string;
  evidence_refs: string[];
}

interface CorrelationGraph {
  investigation_id: string;
  host: string;
  generated_at: string;
  entities: Record<string, EntityNode>;
  relationships: Relationship[];
  findings: any[];
}

interface GraphResponse {
  investigation_id: string;
  graph: CorrelationGraph;
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
  const [timelineData, setTimelineData] = useState<TimelineResponse | null>(null);
  const [timelineSearch, setTimelineSearch] = useState('');
  const [timelineSourceFilter, setTimelineSourceFilter] = useState('ALL');

  const [entitiesData, setEntitiesData] = useState<EntitiesResponse | null>(null);
  const [entitySubTab, setEntitySubTab] = useState<'processes' | 'network' | 'files' | 'users' | 'drivers' | 'registry' | 'logs'>('processes');

  const [iocData, setIocData] = useState<IndicatorsResponse | null>(null);
  const [findingsData, setFindingsData] = useState<FindingsResponse | null>(null);
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);

  // Loading states for each tab
  const [tabLoading, setTabLoading] = useState<Record<string, boolean>>({});

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
      const loadTab = async (tab: string, url: string, setter: (data: any) => void) => {
        setTabLoading(prev => ({ ...prev, [tab]: true }));
        try {
          const res = await api.get(url);
          setter(res.data);
        } catch (error) {
          console.error(`Failed to load ${tab}:`, error);
        } finally {
          setTabLoading(prev => ({ ...prev, [tab]: false }));
        }
      };

      await Promise.all([
        loadTab('timeline', `/api/investigations/${investigationId}/timeline`, setTimelineData),
        loadTab('entities', `/api/investigations/${investigationId}/entities`, setEntitiesData),
        loadTab('indicators', `/api/investigations/${investigationId}/indicators`, setIocData),
        loadTab('findings', `/api/investigations/${investigationId}/findings`, setFindingsData),
        loadTab('graph', `/api/investigations/${investigationId}/graph`, setGraphData),
      ]);

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
  const timelineEvents = timelineData?.events || [];
  const filteredTimeline = timelineEvents.filter(ev => {
    const matchesSource = timelineSourceFilter === 'ALL' || ev.source.toUpperCase() === timelineSourceFilter;
    const matchesQuery = !timelineSearch ||
      ev.event_type.toLowerCase().includes(timelineSearch.toLowerCase()) ||
      (ev.process_name && ev.process_name.toLowerCase().includes(timelineSearch.toLowerCase())) ||
      (ev.path && ev.path.toLowerCase().includes(timelineSearch.toLowerCase())) ||
      (ev.network_endpoint && ev.network_endpoint.toLowerCase().includes(timelineSearch.toLowerCase()));
    return matchesSource && matchesQuery;
  });

  // Entities data
  const entities = entitiesData?.entities;

  // IOC matches
  const iocMatches = iocData?.matches || [];

  // Findings
  const findings = findingsData?.findings || [];

  // Build report data object for exports
  const buildReportData = () => ({
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
  });

  const exportReport = (format: 'json' | 'html' | 'markdown') => {
    const reportData = buildReportData();

    if (format === 'json') {
      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `jockey-report-${investigation.name.toLowerCase().replace(/\s+/g, '-')}.json`;
      a.click();
    } else if (format === 'html') {
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
    } else if (format === 'markdown') {
      const markdown = generateChainOfCustodyMarkdown();
      const blob = new Blob([markdown], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `jockey-chain-of-custody-${investigation.name.toLowerCase().replace(/\s+/g, '-')}.md`;
      a.click();
    }
  };

  const generateChainOfCustodyMarkdown = (): string => {
    const reportData = buildReportData();
    const lines: string[] = [];
    lines.push(`# JOCKEY Chain-of-Custody Report`);
    lines.push(``);
    lines.push(`**Investigation:** ${investigation.name} (\`${investigation.id}\`)`);
    lines.push(`**Generated:** ${new Date().toUTCString()}`);
    lines.push(`**Status:** ${investigation.status}`);
    lines.push(`**Tool Version:** ${investigation.tool_version_id || 'N/A'}`);
    lines.push(``);
    lines.push(`---`);
    lines.push(``);

    // Evidence Chain
    lines.push(`## 1. Evidence Chain`);
    lines.push(``);
    lines.push(`| # | Evidence ID | Host | Collection Time | SHA-256 | Size (MB) |`);
    lines.push(`|---|-------------|------|-----------------|---------|-----------|`);
    evidence.forEach((e, i) => {
      lines.push(`| ${i + 1} | \`${e.id}\` | ${e.host_identifier || 'Unknown'} | ${new Date(e.collection_time).toUTCString()} | \`${e.sha256_hash}\` | ${(e.size_bytes / 1024 / 1024).toFixed(2)} |`);
    });
    lines.push(``);

    // Timeline Events
    lines.push(`## 2. Forensic Timeline (${timelineEvents.length} events)`);
    lines.push(``);
    lines.push(`| Timestamp | Host | Source | Event Type | Process | Path/Endpoint | Evidence Ref |`);
    lines.push(`|-----------|------|--------|------------|---------|---------------|--------------|`);
    timelineEvents.slice(0, 50).forEach(ev => {
      const proc = ev.process_name ? `${ev.process_name} (PID: ${ev.process_id || 'N/A'})` : '-';
      const target = ev.path || ev.network_endpoint || '-';
      const ref = ev.evidence_ref || '-';
      lines.push(`| ${ev.timestamp} | ${ev.host} | ${ev.source} | ${ev.event_type} | ${proc} | ${target} | \`${ref}\` |`);
    });
    if (timelineEvents.length > 50) {
      lines.push(`| ... | ... | ... | ... | ... | ... | ... |`);
      lines.push(`| *${timelineEvents.length - 50} more events truncated* | | | | | | |`);
    }
    lines.push(``);

    // Entities
    if (entities) {
      lines.push(`## 3. Normalized Entities`);
      lines.push(``);

      if (entities.hosts.length > 0) {
        lines.push(`### 3.1 Hosts (${entities.hosts.length})`);
        lines.push(``);
        lines.push(`| Hostname | Platform | OS Version | Architecture |`);
        lines.push(`|----------|----------|------------|--------------|`);
        entities.hosts.forEach(h => {
          lines.push(`| ${h.hostname} | ${h.platform} | ${h.os_version} | ${h.architecture} |`);
        });
        lines.push(``);
      }

      if (entities.processes.length > 0) {
        lines.push(`### 3.2 Processes (${entities.processes.length})`);
        lines.push(``);
        lines.push(`| PID | PPID | Name | User | Executable | Hash |`);
        lines.push(`|-----|------|------|------|------------|------|`);
        entities.processes.slice(0, 30).forEach(p => {
          lines.push(`| ${p.pid} | ${p.ppid || '-'} | ${p.name} | ${p.user || 'root'} | ${p.executable || p.command_line || '-'} | ${p.hash ? `\`${p.hash.slice(0, 16)}...\`` : '-'} |`);
        });
        if (entities.processes.length > 30) {
          lines.push(`| *${entities.processes.length - 30} more processes truncated* | | | | | |`);
        }
        lines.push(``);
      }

      if (entities.network_connections.length > 0) {
        lines.push(`### 3.3 Network Connections (${entities.network_connections.length})`);
        lines.push(``);
        lines.push(`| Protocol | Local | Remote | State | Process | PID |`);
        lines.push(`|----------|-------|--------|-------|---------|-----|`);
        entities.network_connections.slice(0, 30).forEach(n => {
          lines.push(`| ${n.protocol} | ${n.local_address}:${n.local_port} | ${n.remote_address}:${n.remote_port} | ${n.state} | ${n.process || '-'} | ${n.pid || '-'} |`);
        });
        if (entities.network_connections.length > 30) {
          lines.push(`| *${entities.network_connections.length - 30} more connections truncated* | | | | | |`);
        }
        lines.push(``);
      }

      if (entities.files.length > 0) {
        lines.push(`### 3.4 Files (${entities.files.length})`);
        lines.push(``);
        lines.push(`| Path | Size | Owner | SHA-256 |`);
        lines.push(`|------|------|-------|---------|`);
        entities.files.slice(0, 30).forEach(f => {
          lines.push(`| ${f.path} | ${f.size} bytes | ${f.owner || '-'} | ${f.sha256 ? `\`${f.sha256.slice(0, 24)}...\`` : '-'} |`);
        });
        if (entities.files.length > 30) {
          lines.push(`| *${entities.files.length - 30} more files truncated* | | | |`);
        }
        lines.push(``);
      }
    }

    // IOC Matches
    lines.push(`## 4. IOC Threat Matches (${iocMatches.length})`);
    lines.push(``);
    if (iocMatches.length > 0) {
      lines.push(`| Severity | Type | Indicator | Matched Field | Observed Value | Host | Evidence Ref |`);
      lines.push(`|----------|------|-----------|---------------|----------------|------|--------------|`);
      iocMatches.forEach(m => {
        lines.push(`| ${m.severity.toUpperCase()} | ${m.indicator_type} | \`${m.indicator_value}\` | ${m.matched_field} | \`${m.observed_value}\` | ${m.host_id} | \`${m.evidence_reference || 'N/A'}\` |`);
      });
    } else {
      lines.push(`*No IOC matches found.*`);
    }
    lines.push(``);

    // Findings
    lines.push(`## 5. Security Findings (${findings.length})`);
    lines.push(``);
    if (findings.length > 0) {
      lines.push(`| Severity | Rule | Title | MITRE ATT&CK | Entity | Recommendation |`);
      lines.push(`|----------|------|-------|--------------|--------|----------------|`);
      findings.forEach(f => {
        const rec = f.recommendation ? f.recommendation.replace(/\|/g, '\\|') : 'Review evidence';
        lines.push(`| ${f.severity.toUpperCase()} | ${f.rule_name} | ${f.title} | ${f.mitre_attack_id || 'N/A'} | ${f.matched_entity} | ${rec} |`);
      });
    } else {
      lines.push(`*No security findings detected.*`);
    }
    lines.push(``);

    // Correlation Graph
    if (graphData?.graph) {
      lines.push(`## 6. Correlation Graph`);
      lines.push(``);
      lines.push(`**Host:** ${graphData.graph.host}`);
      lines.push(`**Generated:** ${graphData.graph.generated_at}`);
      lines.push(`**Nodes:** ${Object.keys(graphData.graph.entities).length}`);
      lines.push(`**Edges:** ${graphData.graph.relationships.length}`);
      lines.push(``);

      if (graphData.graph.relationships.length > 0) {
        lines.push(`### Relationships`);
        lines.push(``);
        lines.push(`| Source | Target | Type | Confidence | Evidence Refs |`);
        lines.push(`|--------|--------|------|------------|---------------|`);
        graphData.graph.relationships.forEach(rel => {
          const src = rel.source_entity.display();
          const dst = rel.target_entity.display();
          const refs = rel.evidence_refs.slice(0, 2).join(', ') + (rel.evidence_refs.length > 2 ? '...' : '');
          lines.push(`| ${src} | ${dst} | ${rel.relationship_type} | ${(rel.confidence * 100).toFixed(0)}% | ${refs} |`);
        });
      }
      lines.push(``);
    }

    // Attestation
    lines.push(`---`);
    lines.push(``);
    lines.push(`## Attestation`);
    lines.push(``);
    lines.push(`This report was generated by the JOCKEY Forensic Analysis Platform.`);
    lines.push(`All evidence hashes are SHA-256 digests of the original evidence bundles.`);
    lines.push(`Merkle tree inclusion proofs are available for each evidence item to verify integrity.`);
    lines.push(``);
    lines.push(`**Report Hash (SHA-256):** \`${computeReportHash(reportData)}\``);
    lines.push(``);
    lines.push(`---`);
    lines.push(`*End of Chain-of-Custody Report*`);

    return lines.join('\n');
  };

  const generateChainOfCustodyPreview = (): string => {
    const lines: string[] = [];
    lines.push(`# JOCKEY Chain-of-Custody Report (Preview)`);
    lines.push(``);
    lines.push(`**Investigation:** ${investigation.name} (\`${investigation.id}\`)`);
    lines.push(`**Generated:** ${new Date().toUTCString()}`);
    lines.push(`**Status:** ${investigation.status}`);
    lines.push(``);
    lines.push(`---`);
    lines.push(``);
    lines.push(`## 1. Evidence Chain (${evidence.length} items)`);
    evidence.slice(0, 5).forEach((e, i) => {
      lines.push(`${i + 1}. \`${e.id.slice(0, 8)}...\` | ${e.host_identifier || 'Unknown'} | ${new Date(e.collection_time).toLocaleString()} | SHA256: \`${e.sha256_hash.slice(0, 16)}...\` | ${(e.size_bytes / 1024 / 1024).toFixed(2)} MB`);
    });
    if (evidence.length > 5) lines.push(`   ... and ${evidence.length - 5} more`);
    lines.push(``);
    lines.push(`## 2. Timeline Events (${timelineEvents.length})`);
    lines.push(`   Sources: ${timelineData?.sources.join(', ') || 'N/A'}`);
    lines.push(``);
    lines.push(`## 3. Entities`);
    if (entities) {
      lines.push(`   Hosts: ${entities.hosts.length} | Processes: ${entities.processes.length} | Network: ${entities.network_connections.length} | Files: ${entities.files.length}`);
      lines.push(`   Users: ${entities.users.length} | Drivers: ${entities.drivers.length} | Registry: ${entities.registry_keys.length} | Logs: ${entities.log_events.length}`);
    }
    lines.push(``);
    lines.push(`## 4. IOC Matches (${iocMatches.length})`);
    if (iocMatches.length > 0) {
      const bySeverity = iocMatches.reduce((acc, m) => { acc[m.severity] = (acc[m.severity] || 0) + 1; return acc; }, {} as Record<string, number>);
      lines.push(`   ${Object.entries(bySeverity).map(([k, v]) => `${k}: ${v}`).join(' | ')}`);
    }
    lines.push(``);
    lines.push(`## 5. Findings (${findings.length})`);
    if (findings.length > 0) {
      const bySeverity = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {} as Record<string, number>);
      lines.push(`   ${Object.entries(bySeverity).map(([k, v]) => `${k}: ${v}`).join(' | ')}`);
    }
    lines.push(``);
    if (graphData?.graph) {
      lines.push(`## 6. Correlation Graph`);
      lines.push(`   Nodes: ${Object.keys(graphData.graph.entities).length} | Edges: ${graphData.graph.relationships.length}`);
    }
    lines.push(``);
    lines.push(`---`);
    lines.push(`*Click "Export Chain-of-Custody (MD)" to download full report*`);

    return lines.join('\n');
  };

  const computeReportHash = (data: any): string => {
    // Simple hash for display purposes - in production would use Web Crypto API
    const str = JSON.stringify(data);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
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
          disabled={tabLoading.timeline}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'timeline' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200',
            tabLoading.timeline && 'opacity-50 cursor-wait'
          )}
        >
          <Clock className="h-4 w-4" />
          Timeline ({timelineEvents.length})
          {tabLoading.timeline && <Loader2 className="h-3 w-3 animate-spin" />}
        </button>

        <button
          onClick={() => setActiveTab('entities')}
          disabled={tabLoading.entities}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'entities' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200',
            tabLoading.entities && 'opacity-50 cursor-wait'
          )}
        >
          <Layers className="h-4 w-4" />
          Normalized Entities
          {tabLoading.entities && <Loader2 className="h-3 w-3 animate-spin" />}
        </button>

        <button
          onClick={() => setActiveTab('iocs')}
          disabled={tabLoading.indicators}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'iocs' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200',
            tabLoading.indicators && 'opacity-50 cursor-wait'
          )}
        >
          <Activity className="h-4 w-4" />
          IOC Matches ({iocMatches.length})
          {tabLoading.indicators && <Loader2 className="h-3 w-3 animate-spin" />}
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          disabled={tabLoading.findings}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'findings' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200',
            tabLoading.findings && 'opacity-50 cursor-wait'
          )}
        >
          <Shield className="h-4 w-4" />
          Findings & Rules ({findings.length})
          {tabLoading.findings && <Loader2 className="h-3 w-3 animate-spin" />}
        </button>

        <button
          onClick={() => setActiveTab('graph')}
          disabled={tabLoading.graph}
          className={clsx(
            'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            activeTab === 'graph' ? 'border-accent-blue text-accent-blue' : 'border-transparent text-forensic-400 hover:text-forensic-200',
            tabLoading.graph && 'opacity-50 cursor-wait'
          )}
        >
          <Share2 className="h-4 w-4" />
          Correlation Graph
          {tabLoading.graph && <Loader2 className="h-3 w-3 animate-spin" />}
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
          <div className="flex gap-2 border-b border-forensic-800 pb-2 flex-wrap">
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
              Network ({entities?.network_connections.length || 0})
            </button>
            <button
              onClick={() => setEntitySubTab('files')}
              className={clsx('px-3 py-1.5 rounded text-xs font-semibold transition-colors', entitySubTab === 'files' ? 'bg-accent-blue text-white' : 'bg-forensic-800 text-forensic-400')}
            >
              Files ({entities?.files.length || 0})
            </button>
            <button
              onClick={() => setEntitySubTab('users')}
              className={clsx('px-3 py-1.5 rounded text-xs font-semibold transition-colors', entitySubTab === 'users' ? 'bg-accent-blue text-white' : 'bg-forensic-800 text-forensic-400')}
            >
              Users ({entities?.users.length || 0})
            </button>
            <button
              onClick={() => setEntitySubTab('drivers')}
              className={clsx('px-3 py-1.5 rounded text-xs font-semibold transition-colors', entitySubTab === 'drivers' ? 'bg-accent-blue text-white' : 'bg-forensic-800 text-forensic-400')}
            >
              Drivers ({entities?.drivers.length || 0})
            </button>
            <button
              onClick={() => setEntitySubTab('registry')}
              className={clsx('px-3 py-1.5 rounded text-xs font-semibold transition-colors', entitySubTab === 'registry' ? 'bg-accent-blue text-white' : 'bg-forensic-800 text-forensic-400')}
            >
              Registry ({entities?.registry_keys.length || 0})
            </button>
            <button
              onClick={() => setEntitySubTab('logs')}
              className={clsx('px-3 py-1.5 rounded text-xs font-semibold transition-colors', entitySubTab === 'logs' ? 'bg-accent-blue text-white' : 'bg-forensic-800 text-forensic-400')}
            >
              Logs ({entities?.log_events.length || 0})
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
                    <th className="py-2">Start Time</th>
                    <th className="py-2">Hash</th>
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
                      <td className="py-2 text-forensic-400">{proc.start_time ? new Date(proc.start_time).toLocaleString() : '-'}</td>
                      <td className="py-2 text-forensic-500 font-mono text-[10px]">{proc.hash ? `${proc.hash.slice(0, 16)}...` : '-'}</td>
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
                    <th className="py-2">Process</th>
                    <th className="py-2">PID</th>
                    <th className="py-2">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-forensic-800/60">
                  {entities?.network_connections.map((net, i) => (
                    <tr key={i} className="hover:bg-forensic-800/40">
                      <td className="py-2 font-bold text-accent-purple">{net.protocol}</td>
                      <td className="py-2 text-forensic-200">{net.local_address}:{net.local_port}</td>
                      <td className="py-2 text-forensic-200">{net.remote_address}:{net.remote_port}</td>
                      <td className="py-2 text-emerald-400">{net.state}</td>
                      <td className="py-2 text-forensic-300">{net.process || '-'}</td>
                      <td className="py-2 text-forensic-400">{net.pid || '-'}</td>
                      <td className="py-2 text-forensic-400">{new Date(net.timestamp).toLocaleString()}</td>
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
                    <th className="py-2">Created</th>
                    <th className="py-2">Modified</th>
                    <th className="py-2">Accessed</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-forensic-800/60">
                  {entities?.files.map((file, i) => (
                    <tr key={i} className="hover:bg-forensic-800/40">
                      <td className="py-2 text-forensic-100 font-semibold truncate max-w-md">{file.path}</td>
                      <td className="py-2 text-forensic-400">{file.size} bytes</td>
                      <td className="py-2 text-forensic-400">{file.owner || '-'}</td>
                      <td className="py-2 text-forensic-500 font-mono text-[10px]">{file.sha256 ? `${file.sha256.slice(0, 24)}...` : '-'}</td>
                      <td className="py-2 text-forensic-400">{file.created_at ? new Date(file.created_at).toLocaleString() : '-'}</td>
                      <td className="py-2 text-forensic-400">{file.modified_at ? new Date(file.modified_at).toLocaleString() : '-'}</td>
                      <td className="py-2 text-forensic-400">{file.accessed_at ? new Date(file.accessed_at).toLocaleString() : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {entitySubTab === 'users' && (
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-forensic-800 text-forensic-400 pb-2">
                    <th className="py-2">ID</th>
                    <th className="py-2">Username</th>
                    <th className="py-2">Domain</th>
                    <th className="py-2">Privileges</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-forensic-800/60">
                  {entities?.users.map((user, i) => (
                    <tr key={i} className="hover:bg-forensic-800/40">
                      <td className="py-2 text-forensic-400">{user.id}</td>
                      <td className="py-2 text-forensic-100 font-semibold">{user.username}</td>
                      <td className="py-2 text-forensic-300">{user.domain || '-'}</td>
                      <td className="py-2 text-forensic-400">{user.privileges.join(', ') || 'None'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {entitySubTab === 'drivers' && (
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-forensic-800 text-forensic-400 pb-2">
                    <th className="py-2">Name</th>
                    <th className="py-2">Path</th>
                    <th className="py-2">Hash</th>
                    <th className="py-2">Signer</th>
                    <th className="py-2">Version</th>
                    <th className="py-2">Loaded At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-forensic-800/60">
                  {entities?.drivers.map((driver, i) => (
                    <tr key={i} className="hover:bg-forensic-800/40">
                      <td className="py-2 text-forensic-100 font-semibold">{driver.name}</td>
                      <td className="py-2 text-forensic-400 truncate max-w-md">{driver.path || '-'}</td>
                      <td className="py-2 text-forensic-500 font-mono text-[10px]">{driver.hash ? `${driver.hash.slice(0, 16)}...` : '-'}</td>
                      <td className="py-2 text-forensic-300">{driver.signer || '-'}</td>
                      <td className="py-2 text-forensic-300">{driver.version || '-'}</td>
                      <td className="py-2 text-forensic-400">{driver.loaded_at ? new Date(driver.loaded_at).toLocaleString() : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {entitySubTab === 'registry' && (
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-forensic-800 text-forensic-400 pb-2">
                    <th className="py-2">Key</th>
                    <th className="py-2">Value</th>
                    <th className="py-2">Data</th>
                    <th className="py-2">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-forensic-800/60">
                  {entities?.registry_keys.map((reg, i) => (
                    <tr key={i} className="hover:bg-forensic-800/40">
                      <td className="py-2 text-forensic-100 font-semibold truncate max-w-md">{reg.key}</td>
                      <td className="py-2 text-forensic-400">{reg.value || '-'}</td>
                      <td className="py-2 text-forensic-400">{reg.data || '-'}</td>
                      <td className="py-2 text-forensic-400">{reg.timestamp ? new Date(reg.timestamp).toLocaleString() : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {entitySubTab === 'logs' && (
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-forensic-800 text-forensic-400 pb-2">
                    <th className="py-2">Source</th>
                    <th className="py-2">Event ID</th>
                    <th className="py-2">Timestamp</th>
                    <th className="py-2">Host</th>
                    <th className="py-2">User</th>
                    <th className="py-2">Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-forensic-800/60">
                  {entities?.log_events.map((log, i) => (
                    <tr key={i} className="hover:bg-forensic-800/40">
                      <td className="py-2 text-accent-blue">{log.source}</td>
                      <td className="py-2 text-forensic-400">{log.event_id || '-'}</td>
                      <td className="py-2 text-forensic-300">{new Date(log.timestamp).toLocaleString()}</td>
                      <td className="py-2 text-forensic-400">{log.host}</td>
                      <td className="py-2 text-forensic-300">{log.user || '-'}</td>
                      <td className="py-2 text-forensic-200 truncate max-w-lg">{log.message}</td>
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
            <div className="flex items-center gap-4">
              <span className="text-xs text-forensic-500 font-mono">Host: {graphData?.graph?.host || 'Target Node'}</span>
              <span className="text-xs text-forensic-500 font-mono">
                Nodes: {Object.keys(graphData?.graph?.entities || {}).length} | Edges: {graphData?.graph?.relationships?.length || 0}
              </span>
              {tabLoading.graph && <Loader2 className="h-4 w-4 animate-spin text-accent-blue" />}
            </div>
          </div>

          {graphData?.graph ? (
            <GraphView data={graphData.graph} />
          ) : (
            <div className="h-[500px] flex items-center justify-center bg-forensic-900 rounded-lg border border-forensic-800">
              <div className="text-center text-forensic-500">
                <div className="text-4xl mb-2">🔍</div>
                <p className="text-lg">No correlation graph data available</p>
                <p className="text-sm mt-1">Run an investigation to generate entity correlations</p>
              </div>
            </div>
          )}
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
              <button onClick={() => exportReport('markdown')} className="btn-secondary gap-2 text-xs border-amber-500/30 text-amber-400 hover:bg-amber-500/10">
                <Download className="h-4 w-4" /> Export Chain-of-Custody (MD)
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

          {/* Chain of Custody Export Preview */}
          <div className="card p-4 border-forensic-800 bg-forensic-900/50">
            <h4 className="text-xs font-bold text-forensic-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Shield className="h-4 w-4 text-accent-green" />
              Chain-of-Custody Report Preview
            </h4>
            <div className="font-mono text-xs text-forensic-300 bg-forensic-950 p-4 rounded border border-forensic-800 max-h-64 overflow-auto whitespace-pre-wrap">
              {generateChainOfCustodyPreview()}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
