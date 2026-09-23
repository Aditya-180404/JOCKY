import { FormEvent, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AlertCircle, ArrowLeft, CheckCircle2, FileUp, Loader2 } from 'lucide-react';
import { api } from '../services/api';
import type { InvestigationResponse, PaginatedResponse } from '../types/api';

export function EvidenceUpload() {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<InvestigationResponse[]>([]);
  const [investigationId, setInvestigationId] = useState('');
  const [hostIdentifier, setHostIdentifier] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingInvestigations, setLoadingInvestigations] = useState(true);
  const [message, setMessage] = useState<{ type: 'error' | 'success'; text: string } | null>(null);

  useEffect(() => {
    const loadInvestigations = async () => {
      try {
        const response = await api.get<PaginatedResponse<InvestigationResponse>>('/api/investigations', {
          params: { per_page: 100 },
        });
        setInvestigations(response.data.data);
      } catch {
        setMessage({ type: 'error', text: 'Investigations could not be loaded.' });
      } finally {
        setLoadingInvestigations(false);
      }
    };

    loadInvestigations();
  }, []);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!investigationId || !file) {
      setMessage({ type: 'error', text: 'Select an investigation and an evidence file.' });
      return;
    }

    setLoading(true);
    setMessage(null);
    const formData = new FormData();
    formData.append('investigation_id', investigationId);
    formData.append('collection_time', new Date().toISOString());
    formData.append('file', file);
    if (hostIdentifier.trim()) {
      formData.append('host_identifier', hostIdentifier.trim());
    }

    try {
      await api.post('/api/evidence', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setMessage({ type: 'success', text: 'Evidence uploaded and hashed by the API.' });
      setTimeout(() => navigate('/evidence'), 700);
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.message || 'Evidence upload failed. Check the API and storage services.',
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <Link to="/evidence" className="inline-flex items-center gap-2 text-sm text-accent-blue hover:text-blue-400">
          <ArrowLeft className="h-4 w-4" />
          Evidence vault
        </Link>
        <h1 className="mt-4 text-2xl font-bold text-forensic-100">Upload evidence</h1>
        <p className="mt-1 text-forensic-400">Evidence is stored through the protected API and hashed before the record is created.</p>
      </div>

      {message && (
        <div className={`rounded-lg border p-4 flex items-start gap-3 ${message.type === 'success' ? 'border-green-500/30 bg-green-500/10 text-green-300' : 'border-red-500/30 bg-red-500/10 text-red-300'}`} role="status">
          {message.type === 'success' ? <CheckCircle2 className="h-5 w-5 shrink-0" /> : <AlertCircle className="h-5 w-5 shrink-0" />}
          <span>{message.text}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="card p-6 space-y-5">
        <div>
          <label htmlFor="investigation" className="label">Investigation</label>
          <select
            id="investigation"
            value={investigationId}
            onChange={(event) => setInvestigationId(event.target.value)}
            className="input"
            disabled={loadingInvestigations || loading}
          >
            <option value="">{loadingInvestigations ? 'Loading investigations...' : 'Select an investigation'}</option>
            {investigations.map((investigation) => (
              <option key={investigation.id} value={investigation.id}>{investigation.name}</option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="hostIdentifier" className="label">Host identifier <span className="text-forensic-500">(optional)</span></label>
          <input id="hostIdentifier" value={hostIdentifier} onChange={(event) => setHostIdentifier(event.target.value)} className="input" placeholder="WIN-01 or lab-host-01" disabled={loading} />
        </div>

        <div>
          <label htmlFor="evidenceFile" className="label">Evidence file</label>
          <input id="evidenceFile" type="file" onChange={(event) => setFile(event.target.files?.[0] || null)} className="block w-full text-sm text-forensic-300 file:mr-4 file:rounded file:border-0 file:bg-forensic-800 file:px-3 file:py-2 file:text-sm file:text-forensic-100 hover:file:bg-forensic-700" disabled={loading} />
          {file && <p className="mt-2 text-xs font-mono text-forensic-500">{file.name} · {file.size.toLocaleString()} bytes</p>}
        </div>

        <div className="flex items-center justify-between gap-3 pt-2">
          <p className="text-xs text-forensic-500">Collection time is recorded when this upload is submitted.</p>
          <button type="submit" className="btn-primary gap-2" disabled={loading || loadingInvestigations}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileUp className="h-4 w-4" />}
            {loading ? 'Uploading...' : 'Upload evidence'}
          </button>
        </div>
      </form>
    </div>
  );
}
