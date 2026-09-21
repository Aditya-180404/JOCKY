import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import MonacoEditor from '@monaco-editor/react';
import { api } from '../services/api';
import { ToolResponse } from '../types/api';
import {
  Play,
  Check,
  Download,
  Upload,
  ChevronDown,
  AlertCircle,
  Info,
  X,
  Loader2,
  Hash,
  GitBranch,
} from 'lucide-react';
import clsx from 'clsx';

const DEFAULT_SOURCE = `investigation "process_triage" {
    collect system_info

    collect processes {
        pid
        name
        parent
        command_line
        start_time
        hash.sha256
    }

    collect network_connections

    export evidence "process_triage.json"
}`;

const TARGETS = [
  { platform: 'linux', arch: 'x64', label: 'Linux x64' },
  { platform: 'linux', arch: 'arm64', label: 'Linux ARM64' },
  { platform: 'windows', arch: 'x64', label: 'Windows x64' },
  { platform: 'windows', arch: 'arm64', label: 'Windows ARM64' },
];

type Diagnostic = {
  severity: 'error' | 'warning' | 'info';
  message: string;
  line: number;
  column: number;
};

export function Editor() {
  const { toolId } = useParams<{ toolId: string }>();
  const [source, setSource] = useState(DEFAULT_SOURCE);
  const [target, setTarget] = useState('linux-x64');
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([]);
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [artifact, setArtifact] = useState<{ name: string; hash: string; size: number } | null>(null);
  const [tool, setTool] = useState<ToolResponse | null>(null);
  const [version, setVersion] = useState<string>('');

  useEffect(() => {
    if (toolId) {
      loadTool(toolId);
    }
  }, [toolId]);

  const loadTool = async (id: string) => {
    try {
      const res = await api.get(`/api/tools/${id}`);
      setTool(res.data);
      if (res.data.versions.length > 0) {
        const latest = res.data.versions[0];
        // In a real app, we'd fetch the source from storage
        setVersion(latest.version);
      }
    } catch (error) {
      console.error('Failed to load tool:', error);
    }
  };

  const handleEditorChange = (value: string | undefined) => {
    if (value !== undefined) {
      setSource(value);
    }
  };

  const handleValidate = async () => {
    setLoading(true);
    setOutput('Validating...');
    setDiagnostics([]);

    try {
      await api.post('/api/tools/validate', { source });
      setOutput('Validation successful');
      // In a real implementation, the API would return diagnostics
    } catch (error: any) {
      const message = error.response?.data?.message || 'Validation failed';
      setOutput(`Validation failed: ${message}`);
      // Parse error for diagnostics
      if (error.response?.data?.diagnostics) {
        setDiagnostics(error.response.data.diagnostics);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCompile = async () => {
    setLoading(true);
    setOutput('Compiling...');
    setArtifact(null);

    const [platform, arch] = target.split('-');

    try {
      if (toolId) {
        // Build existing tool version
        const res = await api.post(`/api/tools/${toolId}/build`, {
          target_platform: platform,
          target_arch: arch,
        });
        setOutput(`Build queued: ${res.data.build_id}`);
        // Poll for build status
        pollBuild(res.data.build_id);
      } else {
        // Create tool and build
        const toolName = extractToolName(source) || 'investigation';
        const createRes = await api.post('/api/tools', {
          name: toolName,
          description: 'Created from IDE',
        });
        const newTool = createRes.data;

        await api.post(`/api/tools/${newTool.id}/versions`, {
          version: '0.1.0',
          source,
          target_platform: platform,
          target_arch: arch,
        });

        const buildRes = await api.post(`/api/tools/${newTool.id}/build`, {
          target_platform: platform,
          target_arch: arch,
        });

        setOutput(`Build queued: ${buildRes.data.build_id}`);
        pollBuild(buildRes.data.build_id);
      }
    } catch (error: any) {
      const message = error.response?.data?.message || 'Compilation failed';
      setOutput(`Compilation failed: ${message}`);
      setLoading(false);
    }
  };

  const pollBuild = async (buildId: string) => {
    const maxAttempts = 60;
    let attempts = 0;

    const checkStatus = async () => {
      try {
        const response = await api.get(`/api/tools/builds/${buildId}`);
        const build = response.data;

        if (build.status === 'success') {
          setOutput('Compilation successful!');
          if (build.artifact_hash) {
            setArtifact({
              name: `${extractToolName(source) || 'tool'}-${target}`,
              hash: build.artifact_hash,
              size: build.artifact_size || 0,
            });
          }
          setLoading(false);
        } else if (build.status === 'failed') {
          setOutput(`Build failed: ${build.build_log || 'Unknown error'}`);
          setLoading(false);
        } else if (attempts < maxAttempts) {
          attempts++;
          setTimeout(checkStatus, 5000);
        } else {
          setOutput('Build timed out');
          setLoading(false);
        }
      } catch {
        if (attempts < maxAttempts) {
          attempts++;
          setTimeout(checkStatus, 5000);
        } else {
          setOutput('Build status check failed');
          setLoading(false);
        }
      }
    };

    checkStatus();
  };

  const handlePublish = async () => {
    if (!toolId) return;
    setLoading(true);
    try {
      await api.post(`/api/tools/${toolId}/publish`);
      setOutput('Tool published successfully!');
    } catch (error: any) {
      setOutput(`Publish failed: ${error.response?.data?.message}`);
    } finally {
      setLoading(false);
    }
  };

  const extractToolName = (src: string): string | null => {
    const match = src.match(/investigation\s+"([^"]+)"/);
    return match ? match[1].replace(/[^a-zA-Z0-9_-]/g, '-') : null;
  };

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 border-b border-forensic-800 bg-forensic-900/50">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold text-forensic-100">TraceForge IDE</h1>
          {tool && (
            <span className="badge badge-info">v{version || '0.1.0'}</span>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative" role="combobox" aria-label="Build target">
            <select
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="input pr-10 appearance-none bg-forensic-800"
              disabled={loading}
            >
              {TARGETS.map((t) => (
                <option key={`${t.platform}-${t.arch}`} value={`${t.platform}-${t.arch}`}>
                  {t.label}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-forensic-500 pointer-events-none" />
          </div>

          <button
            onClick={handleValidate}
            disabled={loading}
            className="btn-secondary btn-sm gap-1"
            title="Validate (Ctrl+Shift+V)"
          >
            <Check className="h-4 w-4" />
            <span className="hidden sm:inline">Validate</span>
          </button>

          <button
            onClick={handleCompile}
            disabled={loading}
            className="btn-primary btn-sm gap-1"
            title="Compile (Ctrl+Shift+B)"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            <span className="hidden sm:inline">{loading ? 'Building...' : 'Compile'}</span>
          </button>

          {tool && tool.versions.some(v => !v.is_published) && (
            <button
              onClick={handlePublish}
              disabled={loading || !artifact}
              className="btn-success btn-sm gap-1"
              title="Publish"
            >
              <Upload className="h-4 w-4" />
              <span className="hidden sm:inline">Publish</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Editor Area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Editor Pane */}
        <div className="flex-1 flex flex-col min-w-0">
          <div className="flex items-center justify-between px-4 py-2 border-b border-forensic-800 bg-forensic-900/50">
            <span className="text-sm text-forensic-400 font-mono">investigation.tfg</span>
            <div className="flex items-center gap-2">
              <span className="text-xs text-forensic-500">TraceForge</span>
            </div>
          </div>

          <div className="flex-1 relative">
            <MonacoEditor
              height="100%"
              defaultLanguage="traceforge"
              value={source}
              onChange={handleEditorChange}
              theme="vs-dark"
              options={ {
                minimap: { enabled: false },
                fontSize: 14,
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                automaticLayout: true,
                tabSize: 4,
                insertSpaces: true,
                wordWrap: 'on',
                bracketPairColorization: { enabled: true },
                guides: { bracketPairs: true },
              } as any }
            />
          </div>
        </div>

        {/* Output/ Diagnostics Panel */}
        <div className="w-96 lg:w-80 border-l border-forensic-800 bg-forensic-900/50 flex flex-col">
          <div className="flex items-center justify-between px-4 py-2 border-b border-forensic-800">
            <h2 className="text-sm font-medium text-forensic-300">Output</h2>
            <button
              onClick={() => setOutput('')}
              className="p-1 text-forensic-500 hover:text-forensic-300 rounded"
              aria-label="Clear output"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="flex-1 overflow-auto p-4" role="log" aria-live="polite">
            {diagnostics.length > 0 && (
              <div className="mb-4 space-y-2">
                <h3 className="text-xs font-medium text-forensic-500 uppercase tracking-wider">Diagnostics</h3>
                {diagnostics.map((diag, i) => (
                  <div key={i} className={clsx('p-3 rounded-lg text-sm border', diag.severity === 'error' && 'bg-red-500/10 border-red-500/20 text-red-400', diag.severity === 'warning' && 'bg-amber-500/10 border-amber-500/20 text-amber-400', diag.severity === 'info' && 'bg-blue-500/10 border-blue-500/20 text-blue-400')}>
                    <div className="flex items-start gap-2">
                      <span className={clsx('flex-shrink-0 mt-0.5', diag.severity === 'error' && 'text-red-400', diag.severity === 'warning' && 'text-amber-400', diag.severity === 'info' && 'text-blue-400')}>
                        {diag.severity === 'error' && <AlertCircle className="h-4 w-4" />}
                        {diag.severity === 'warning' && <AlertCircle className="h-4 w-4" />}
                        {diag.severity === 'info' && <Info className="h-4 w-4" />}
                      </span>
                      <div>
                        <p className="font-mono text-xs text-forensic-500">Line {diag.line}, Col {diag.column}</p>
                        <p>{diag.message}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="code-block font-mono text-sm text-forensic-300 whitespace-pre-wrap font-mono">
              {output || <span className="text-forensic-600">Ready. Write your investigation and click Compile.</span>}
            </div>
          </div>

          {artifact && (
            <div className="p-4 border-t border-forensic-800 bg-forensic-900/50">
              <h3 className="text-sm font-medium text-forensic-300 mb-3 flex items-center gap-2">
                <Hash className="h-4 w-4" />
                Artifact Generated
              </h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-forensic-500">Name</span>
                  <span className="text-forensic-100 font-mono">{artifact.name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-forensic-500">SHA-256</span>
                  <span className="text-forensic-100 font-mono truncate max-w-[150px]">{artifact.hash}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-forensic-500">Size</span>
                  <span className="text-forensic-100">{(artifact.size / 1024 / 1024).toFixed(2)} MB</span>
                </div>
              </div>
              <div className="mt-3 flex gap-2">
                <button className="btn-secondary btn-sm flex-1 gap-1">
                  <Download className="h-4 w-4" />
                  Download
                </button>
                <button className="btn-primary btn-sm flex-1 gap-1">
                  <GitBranch className="h-4 w-4" />
                  Publish
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}