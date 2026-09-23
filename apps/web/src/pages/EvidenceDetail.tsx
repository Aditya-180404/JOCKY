import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../services/api';
import { EvidenceResponse } from '../types/api';
import {
  ArrowLeft,
  Hash,
  CheckCircle,
  AlertCircle,
  Loader2,
  Download,
  Copy,
  FileText,
  Shield,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';

export function EvidenceDetail() {
  const { id } = useParams<{ id: string }>();
  const [evidence, setEvidence] = useState<EvidenceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      loadEvidence(id);
    }
  }, [id]);

  const loadEvidence = async (evidenceId: string) => {
    setLoading(true);
    try {
      const response = await api.get(`/api/evidence/${evidenceId}`);
      setEvidence(response.data.evidence);
      setDownloadUrl(response.data.download_url);
    } catch (error) {
      console.error('Failed to load evidence:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    if (!id) return;
    setVerifying(true);
    setVerified(null);
    try {
      const response = await api.post(`/api/evidence/${id}/verify`);
      setVerified(response.data.valid);
    } catch (error) {
      setVerified(false);
    } finally {
      setVerifying(false);
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

  if (!evidence) {
    return (
      <div className="text-center py-12">
        <AlertCircle className="h-16 w-16 text-accent-red mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-forensic-100 mb-2">Evidence not found</h2>
        <Link to="/evidence" className="text-accent-blue hover:text-blue-400">
          Back to evidence vault
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <Link to="/evidence" className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-forensic-100">Evidence Details</h1>
              {verified !== null && (
                <span className={clsx('badge flex items-center gap-1.5', verified ? 'badge-success' : 'badge-danger')}>
                  {verified ? (
                    <>
                      <CheckCircle className="h-3 w-3" />
                      Verified
                    </>
                  ) : (
                    <>
                      <AlertCircle className="h-3 w-3" />
                      Verification Failed
                    </>
                  )}
                </span>
              )}
            </div>
            <p className="text-forensic-400 mt-1">Investigation: {evidence.investigation_id.substring(0, 8)}...</p>
          </div>
        </div>
        <div className="flex gap-2">
          {downloadUrl && (
            <a href={downloadUrl} className="btn-secondary gap-2" target="_blank" rel="noopener noreferrer">
              <Download className="h-4 w-4" />
              Download
            </a>
          )}
        </div>
      </div>

      {/* Verification Card */}
      <div className="card p-5 border-accent-blue/30 bg-accent-blue/5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-accent-blue" />
            <div>
              <h3 className="font-semibold text-forensic-100">Integrity Verification</h3>
              <p className="text-sm text-forensic-400">Verify SHA-256 hash matches stored value</p>
            </div>
          </div>
          <button
            onClick={handleVerify}
            disabled={verifying || verified !== null}
            className={clsx('btn-primary gap-2', verifying && 'opacity-75')}
          >
            {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <Hash className="h-4 w-4" />}
            {verifying ? 'Verifying...' : verified !== null ? 'Verified' : 'Verify Integrity'}
          </button>
        </div>
      </div>

      {/* Details Grid */}
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className="card p-4">
          <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">SHA-256 Hash</p>
          <div className="flex items-center gap-2">
            <code className="font-mono text-sm text-forensic-300 flex-1 break-all">{evidence.sha256_hash}</code>
            <button
              onClick={() => copyToClipboard(evidence.sha256_hash, 'hash')}
              className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors flex-shrink-0"
              title={copied === 'hash' ? 'Copied!' : 'Copy hash'}
            >
              {copied === 'hash' ? <CheckCircle className="h-4 w-4 text-accent-green" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
        </div>

        <div className="card p-4">
          <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Size</p>
          <p className="font-mono text-lg text-forensic-100">{(evidence.size_bytes / 1024 / 1024).toFixed(2)} MB</p>
        </div>

        <div className="card p-4">
          <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Collected</p>
          <p className="font-mono text-sm text-forensic-300">
            {formatDistanceToNow(new Date(evidence.collection_time), { addSuffix: true })}
          </p>
        </div>

        <div className="card p-4">
          <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Host</p>
          <p className="font-mono text-sm text-forensic-300">{evidence.host_identifier || 'Unknown'}</p>
        </div>

        <div className="card p-4">
          <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Investigation</p>
          <Link to={`/investigations/${evidence.investigation_id}`} className="font-mono text-sm text-accent-blue hover:text-blue-400 truncate block">
            {evidence.investigation_id}
          </Link>
        </div>

        <div className="card p-4">
          <p className="text-xs text-forensic-500 uppercase tracking-wider mb-1">Tool Version</p>
          <p className="font-mono text-sm text-forensic-300">
            {evidence.tool_version_id ? evidence.tool_version_id.substring(0, 8) + '...' : 'N/A'}
          </p>
        </div>
      </div>

      {/* Metadata */}
      {evidence.metadata && Object.keys(evidence.metadata).length > 0 && (
        <section className="card">
          <div className="p-5 border-b border-forensic-800">
            <h2 className="text-lg font-semibold text-forensic-100 flex items-center gap-2">
              <FileText className="h-5 w-5 text-accent-purple" />
              Metadata
            </h2>
          </div>
          <div className="p-5">
            <div className="code-block">
              <pre className="text-forensic-300"><code>{JSON.stringify(evidence.metadata, null, 2)}</code></pre>
            </div>
          </div>
        </section>
      )}

      {/* Merkle Proof */}
      {evidence.merkle_proof && (
        <section className="card">
          <div className="p-5 border-b border-forensic-800">
            <h2 className="text-lg font-semibold text-forensic-100 flex items-center gap-2">
              <Hash className="h-5 w-5 text-accent-amber" />
              Merkle Proof
            </h2>
          </div>
          <div className="p-5">
            <div className="code-block">
              <pre className="text-forensic-300"><code>{JSON.stringify(evidence.merkle_proof, null, 2)}</code></pre>
            </div>
          </div>
        </section>
      )}

      {/* Storage Info */}
      <section className="card">
        <div className="p-5 border-b border-forensic-800">
          <h2 className="text-lg font-semibold text-forensic-100 flex items-center gap-2">
            <FileText className="h-5 w-5 text-accent-green" />
            Storage Information
          </h2>
        </div>
        <div className="p-5 space-y-3">
          <div className="flex justify-between">
            <span className="text-forensic-500">Storage Path</span>
            <code className="font-mono text-sm text-forensic-300 truncate max-w-[300px]">{evidence.storage_path}</code>
          </div>
          <div className="flex justify-between">
            <span className="text-forensic-500">Uploaded</span>
            <span className="font-mono text-sm text-forensic-300">
              {formatDistanceToNow(new Date(evidence.created_at), { addSuffix: true })}
            </span>
          </div>
        </div>
      </section>
    </div>
  );
}