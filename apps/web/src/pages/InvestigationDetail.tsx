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

export function InvestigationDetail() {
  const { id } = useParams<{ id: string }>();
  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null);
  const [evidence, setEvidence] = useState<EvidenceSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

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
      // Reload to get updated status
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
            <p className="text-forensic-400 mt-1">{investigation.description || 'No description'}</p>
          </div>
        </div>
        <div className="flex gap-2">
          {investigation.status === 'draft' && investigation.tool_version_id && (
            <button
              onClick={handleRun}
              disabled={running}
              className="btn-primary gap-2"
            >
              {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {running ? 'Running...' : 'Run Investigation'}
            </button>
          )}
          <Link to="/editor" className="btn-secondary gap-2">
            <Plus className="h-4 w-4" />
            New Investigation
          </Link>
        </div>
      </div>

      {/* Metadata */}
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

      {/* Evidence Section */}
      <section className="card">
        <div className="p-5 border-b border-forensic-800 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-forensic-100 flex items-center gap-2">
            <Search className="h-5 w-5 text-accent-purple" />
            Collected Evidence ({evidence.length})
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
                Run the investigation tool on target machines, then upload the evidence files here for verification.
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
                      {item.host_identifier || 'Unknown host'}
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

      {/* Verification Note */}
      <div className="card p-4 border-accent-blue/30 bg-accent-blue/5">
        <div className="flex items-start gap-3">
          <Hash className="h-5 w-5 text-accent-blue flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-medium text-forensic-100 mb-1">Evidence Integrity Verification</h3>
            <p className="text-sm text-forensic-400">
              All evidence is automatically hashed with SHA-256 upon upload. Use the Evidence page to verify
              file integrity against stored hashes. Merkle tree batching and blockchain anchoring available
              for additional tamper-proof guarantees.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}