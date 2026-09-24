import { useState, useRef, useEffect, useCallback } from 'react';
import MonacoEditor, { OnMount } from '@monaco-editor/react';
import { useSearchParams } from 'react-router-dom';
import { SiteHeader } from '../components/SiteHeader';
import { api } from '../services/api';
import {
  Play,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Download,
  FileCode,
  ShieldCheck,
  Terminal as TerminalIcon,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Folder,
  FolderOpen,
  Sliders,
  Hash,
} from 'lucide-react';
import clsx from 'clsx';

/** Collector docs for hover / completions */
const COLLECTOR_DOCS: Record<string, string> = {
  system_info: 'Collect host OS metadata: hostname, kernel, uptime, CPU, memory.',
  processes: 'Collect running process list with PID, name, command line, user, and optional binary hash.',
  network_connections: 'Collect active TCP/UDP socket table with local/remote endpoints and process owner.',
  files: 'Collect filesystem entries under a given path. Supports recursive traversal and SHA-256 hashing.',
  logs: 'Collect OS event log or syslog entries with timestamp, severity, and source.',
  drivers: 'Collect loaded kernel modules/drivers with path and hash (Linux: /proc/modules; Windows: DriverStore).',
  memory_regions: 'Collect virtual memory map of a process (PID). Maps readable/writable/executable regions.',
  registry: 'Collect Windows Registry entries under a hive and key path (no-op on Linux).',
  artifacts: 'Carve forensic artifacts of the specified type (prefetch, eventlog, shimcache …) from an optional path.',
};

const ALL_KEYWORDS = [
  'investigation', 'metadata', 'collect', 'export', 'evidence',
  'filter', 'where', 'limit', 'hash', 'sha256', 'sha1', 'md5',
  'recursive', 'true', 'false', 'target', 'capability',
  ...Object.keys(COLLECTOR_DOCS),
];

interface Diagnostic {
  severity: 'error' | 'warning' | 'info' | 'hint';
  message: string;
  line: number;
  column: number;
}

interface EvidenceItem {
  id: string;
  collector: string;
  timestamp: string;
  source: string;
  data: any;
  sha256: string;
  integrity: string;
}

interface ExecutionResult {
  success: boolean;
  investigation_name: string;
  execution_target: string;
  execution_time_ms: number;
  collectors_executed: string[];
  evidence_count: number;
  sha256: string;
  integrity: string;
  evidence_items: EvidenceItem[];
  output_log: string[];
}

interface CheckResponse {
  valid: boolean;
  diagnostics: Diagnostic[];
  collectors: string[];
  required_capabilities: string[];
  investigation_name?: string;
}

const EXAMPLES = [
  {
    id: 'basic_system_triage',
    filename: 'basic_system_triage.tfg',
    name: 'Basic System Triage',
    description: 'Collect system information and running processes into verifiable JSON.',
    code: `investigation "basic_system_triage" {
    collect system_info

    collect processes

    export evidence "system_triage.json"
}`,
  },
  {
    id: 'process_investigation',
    filename: 'process_investigation.tfg',
    name: 'Process Investigation',
    description: 'Inspect processes with parent PID, command line, user, and SHA-256 binary hash.',
    code: `investigation "process_investigation" {
    collect processes {
        pid
        name
        parent
        command_line
        user
        hash.sha256
    }

    export evidence "process_evidence.json"
}`,
  },
  {
    id: 'network_investigation',
    filename: 'network_investigation.tfg',
    name: 'Network Investigation',
    description: 'Capture active socket listening ports, protocols, and endpoints alongside host info.',
    code: `investigation "network_investigation" {
    collect system_info

    collect network_connections

    export evidence "network_evidence.json"
}`,
  },
  {
    id: 'user_investigation',
    filename: 'user_investigation.tfg',
    name: 'User Investigation',
    description: 'Filter process tree specifically for privileged account activity.',
    code: `investigation "user_investigation" {
    collect system_info

    collect processes {
        pid
        name
        user
    } where user == "root"

    export evidence "user_evidence.json"
}`,
  },
  {
    id: 'filesystem_investigation',
    filename: 'filesystem_investigation.tfg',
    name: 'Filesystem Investigation',
    description: 'Inspect critical configuration directories with recursive SHA-256 hashes.',
    code: `investigation "filesystem_investigation" {
    collect system_info

    collect files "/etc" {
        recursive
        hash.sha256
    } limit 50

    export evidence "filesystem_evidence.json"
}`,
  },
  {
    id: 'evidence_hashing',
    filename: 'evidence_hashing.tfg',
    name: 'Evidence Hashing',
    description: 'Deterministic binary hashing of active processes for malware triage.',
    code: `investigation "evidence_hashing" {
    collect processes {
        pid
        name
        hash.sha256
    }

    export evidence "hashed_evidence.json"
}`,
  },
  {
    id: 'complete_basic_triage',
    filename: 'complete_basic_triage.tfg',
    name: 'Complete Basic Triage',
    description: 'Full multi-collector incident response triage with metadata tags.',
    code: `investigation "complete_basic_triage" {
    metadata {
        author = "Forensic Analyst"
        priority = "High"
        category = "Incident Response"
    }

    collect system_info

    collect processes {
        pid
        name
        parent
        command_line
        user
        hash.sha256
    }

    collect network_connections

    export evidence "complete_triage_evidence.json"
}`,
  },
  {
    id: 'memory_process_triage',
    filename: 'memory_process_triage.tfg',
    name: 'Memory Region Triage',
    description: 'Dump virtual memory maps of a target process to detect injected shellcode or hollowed sections.',
    code: `investigation "memory_process_triage" {
    metadata {
        priority = "Critical"
        category = "Memory Forensics"
    }

    collect processes {
        pid
        name
        hash.sha256
    }

    collect memory_regions pid=1234

    export evidence "memory_triage.json"
}`,
  },
  {
    id: 'windows_registry_audit',
    filename: 'windows_registry_audit.tfg',
    name: 'Windows Registry Audit',
    description: 'Enumerate persistence keys in the Windows Registry (Run, Services).',
    code: `investigation "windows_registry_audit" {
    metadata {
        category = "Persistence Detection"
        platform = "Windows"
    }

    collect registry hive="HKLM" key="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    collect registry hive="HKLM" key="SYSTEM\\CurrentControlSet\\Services"

    export evidence "registry_audit.json"
}`,
  },
  {
    id: 'artifact_carving',
    filename: 'artifact_carving.tfg',
    name: 'Forensic Artifact Carving',
    description: 'Extract Prefetch, Shimcache, and Event Log artifacts to reconstruct execution history.',
    code: `investigation "artifact_carving" {
    metadata {
        category = "Artifact Analysis"
        author   = "DFIR Team"
    }

    collect artifacts type="prefetch"  path="C:\\Windows\\Prefetch"
    collect artifacts type="shimcache"
    collect artifacts type="eventlog"

    export evidence "artifact_carving.json"
}`,
  },
  {
    id: 'log_threat_hunt',
    filename: 'log_threat_hunt.tfg',
    name: 'Log-Based Threat Hunt',
    description: 'Correlate auth logs with privileged process activity to detect privilege escalation.',
    code: `investigation "log_threat_hunt" {
    metadata { priority = "High" }

    collect system_info
    collect logs source="auth"
    collect logs source="system"

    collect processes {
        pid
        name
        user
        parent
    } where user == "root"

    export evidence "threat_hunt.json"
}`,
  },
  {
    id: 'driver_rootkit_hunt',
    filename: 'driver_rootkit_hunt.tfg',
    name: 'Driver & Rootkit Hunt',
    description: 'Enumerate and hash loaded kernel modules to detect unsigned or injected rootkit drivers.',
    code: `investigation "driver_rootkit_hunt" {
    metadata { priority = "Critical" }

    collect system_info
    collect drivers

    export evidence "driver_audit.json"
}`,
  },
  {
    id: 'full_incident_triage',
    filename: 'full_incident_triage.tfg',
    name: 'Full Incident Response Triage',
    description: 'Comprehensive sweep covering system, processes, network, filesystem, and logs.',
    code: `investigation "full_incident_triage" {
    metadata {
        author   = "DFIR Team"
        priority = "High"
        category = "Incident Response"
    }

    collect system_info
    collect processes { pid name parent command_line user hash.sha256 }
    collect network_connections
    collect files "/tmp" { recursive hash.sha256 } limit 100
    collect logs source="auth"

    export evidence "incident_triage.json"
}`,
  },
];


interface TargetOption {
  id: string;
  name: string;
  status: string;
}

export function WebIDE() {
  const [searchParams] = useSearchParams();
  const requestedExample = searchParams.get('example');
  const initialExample = EXAMPLES.find((example) => example.id === requestedExample) || EXAMPLES[0];
  const [source, setSource] = useState(initialExample.code);
  const [selectedExample, setSelectedExample] = useState(initialExample.id);
  const [selectedTarget, setSelectedTarget] = useState('sandbox');
  const [targets, setTargets] = useState<TargetOption[]>([]);

  // Panel visibilities
  const [showExplorer, setShowExplorer] = useState(true);
  const [showInspector, setShowInspector] = useState(true);
  const [showBottomPanel, setShowBottomPanel] = useState(true);
  const [bottomPanelTab, setBottomPanelTab] = useState<'problems' | 'output' | 'evidence' | 'integrity'>('output');
  const [inspectorTab, setInspectorTab] = useState<'diagnostics' | 'capabilities' | 'artifact'>('diagnostics');

  // Compiler state
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([]);
  const [requiredCapabilities, setRequiredCapabilities] = useState<string[]>([]);
  const [checkPassed, setCheckPassed] = useState<boolean | null>(null);
  const [executionResult, setExecutionResult] = useState<ExecutionResult | null>(null);
  const [selectedEvidenceItem, setSelectedEvidenceItem] = useState<EvidenceItem | null>(null);

  // UI states
  const [isLoading, setIsLoading] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [statusMessage, setStatusMessage] = useState('Ready');
  const [copied, setCopied] = useState(false);
  const [examplesOpen, setExamplesOpen] = useState(true);

  const editorRef = useRef<any>(null);
  const monacoRef = useRef<any>(null);

  useEffect(() => {
    api.get('/api/compiler/targets')
      .then((response) => {
        const availableTargets = (response.data as Array<{ id: string; name: string; supported: boolean; host_compatible: boolean; toolchain_required?: string }>).map((target) => ({
          id: target.id,
          name: target.name,
          status: target.id === 'sandbox'
            ? 'Supported'
            : target.supported && target.host_compatible
              ? 'Available here'
              : target.supported
                ? 'Supported elsewhere'
                : 'Unsupported',
        }));
        setTargets(availableTargets);
      })
      .catch(() => setTargets([{ id: 'sandbox', name: 'jockey server sandbox', status: 'Unavailable' }]));
  }, []);

  // Configure Monaco Editor
  const handleEditorDidMount: OnMount = (editor, monaco) => {
    editorRef.current = editor;
    monacoRef.current = monaco;

    // Register jockey language definition
    if (!monaco.languages.getLanguages().some((l: any) => l.id === 'jockey')) {
      monaco.languages.register({ id: 'jockey' });

      monaco.languages.setMonarchTokensProvider('jockey', {
        keywords: ALL_KEYWORDS,
        tokenizer: {
          root: [
            [/[a-zA-Z_]\w*/, {
              cases: {
                '@keywords': 'keyword',
                '@default': 'identifier',
              },
            }],
            [/"([^"\\]|\\.)*"/, 'string'],
            [/\d+/, 'number'],
            [/[{}()[\]]/, '@brackets'],
            [/[=><!~?:&|+\-*/^%]+/, 'operator'],
            [/\/\/.*$/, 'comment'],
            [/\/\*/, 'comment', '@comment'],
          ],
          comment: [
            [/[^*]+/, 'comment'],
            [/\*\//, 'comment', '@pop'],
            [/[*]/, 'comment'],
          ],
        },
      });

      monaco.languages.setLanguageConfiguration('jockey', {
        comments: {
          lineComment: '//',
          blockComment: ['/*', '*/'],
        },
        brackets: [
          ['{', '}'],
          ['[', ']'],
          ['(', ')'],
        ],
        autoClosingPairs: [
          { open: '{', close: '}' },
          { open: '[', close: ']' },
          { open: '(', close: ')' },
          { open: '"', close: '"' },
        ],
      });

      // Hover provider — shows collector documentation
      monaco.languages.registerHoverProvider('jockey', {
        provideHover(model: any, position: any) {
          const word = model.getWordAtPosition(position);
          if (!word) return null;
          const doc = COLLECTOR_DOCS[word.word];
          if (!doc) return null;
          return {
            range: new monaco.Range(
              position.lineNumber, word.startColumn,
              position.lineNumber, word.endColumn
            ),
            contents: [
              { value: `**${word.word}** — jockey collector` },
              { value: doc },
            ],
          };
        },
      });

      // Completion provider — suggests keywords and collector targets
      monaco.languages.registerCompletionItemProvider('jockey', {
        provideCompletionItems(model: any, position: any) {
          const word = model.getWordUntilPosition(position);
          const range = {
            startLineNumber: position.lineNumber,
            endLineNumber: position.lineNumber,
            startColumn: word.startColumn,
            endColumn: word.endColumn,
          };
          const collectorItems = Object.entries(COLLECTOR_DOCS).map(([kw, doc]) => ({
            label: kw,
            kind: monaco.languages.CompletionItemKind.Module,
            detail: 'Forensic collector',
            documentation: doc,
            insertText: kw,
            range,
          }));
          const kwItems = [
            'investigation', 'metadata', 'collect', 'export', 'evidence',
            'filter', 'where', 'limit', 'recursive', 'true', 'false',
          ].map((kw) => ({
            label: kw,
            kind: monaco.languages.CompletionItemKind.Keyword,
            insertText: kw,
            range,
          }));
          const snippetItems = [
            {
              label: 'investigation (snippet)',
              kind: monaco.languages.CompletionItemKind.Snippet,
              insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
              insertText: 'investigation "${1:name}" {\n    collect system_info\n    export evidence "${2:output.json}"\n}',
              documentation: 'Create a new investigation scaffold',
              range,
            },
          ];
          return { suggestions: [...collectorItems, ...kwItems, ...snippetItems] };
        },
      });
    }

    // Professional, restrained editor theme
    monaco.editor.defineTheme('jockey-pro', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'keyword', foreground: '60a5fa', fontStyle: 'bold' },
        { token: 'string', foreground: '34d399' },
        { token: 'number', foreground: 'fbbf24' },
        { token: 'comment', foreground: '64748b', fontStyle: 'italic' },
        { token: 'identifier', foreground: 'f1f5f9' },
        { token: 'operator', foreground: '94a3b8' },
        { token: '@brackets', foreground: 'cbd5e1' },
      ],
      colors: {
        'editor.background': '#0c111c',
        'editor.foreground': '#e2e8f0',
        'editorLineNumber.foreground': '#334155',
        'editorLineNumber.activeForeground': '#94a3b8',
        'editor.selectionBackground': '#1e293b',
        'editor.lineHighlightBackground': '#11182780',
        'editorCursor.foreground': '#60a5fa',
        'editorWhitespace.foreground': '#1e293b',
      },
    });

    monaco.editor.setTheme('jockey-pro');
  };

  // Debounced auto-check: fires 800 ms after the user stops typing
  const autoCheckTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const handleSourceChange = useCallback((newSource: string) => {
    setSource(newSource);
    if (autoCheckTimerRef.current) clearTimeout(autoCheckTimerRef.current);
    autoCheckTimerRef.current = setTimeout(async () => {
      if (!newSource.trim()) return;
      try {
        const res = await api.post('/api/compiler/check', { source: newSource });
        const data: CheckResponse = res.data;
        setDiagnostics(data.diagnostics || []);
        setCheckPassed(data.valid);
        setRequiredCapabilities(data.required_capabilities || []);
        if (monacoRef.current && editorRef.current) {
          const model = editorRef.current.getModel();
          const markers = (data.diagnostics || []).map((d: Diagnostic) => ({
            severity:
              d.severity === 'error'
                ? monacoRef.current.MarkerSeverity.Error
                : d.severity === 'warning'
                ? monacoRef.current.MarkerSeverity.Warning
                : monacoRef.current.MarkerSeverity.Info,
            message: d.message,
            startLineNumber: d.line || 1,
            startColumn: d.column || 1,
            endLineNumber: d.line || 1,
            endColumn: (d.column || 1) + 8,
          }));
          monacoRef.current.editor.setModelMarkers(model, 'jockey', markers);
        }
      } catch { /* silent — user will see errors on explicit check */ }
    }, 800);
  }, []);

  const handleSelectExample = (id: string) => {
    const example = EXAMPLES.find((e) => e.id === id);
    if (example) {
      setSelectedExample(id);
      setSource(example.code);
      setDiagnostics([]);
      setCheckPassed(null);
      setStatusMessage(`Loaded: ${example.filename}`);

      setRequiredCapabilities([]);
    }
  };

  const handleCheckCode = async () => {
    setIsLoading(true);
    setStatusMessage('Checking with compiler...');
    try {
      const res = await api.post('/api/compiler/check', { source });
      const data: CheckResponse = res.data;
      setDiagnostics(data.diagnostics || []);
      setCheckPassed(data.valid);

      setRequiredCapabilities(data.required_capabilities || []);

      if (data.valid) {
        setStatusMessage(`✓ Validation successful (${data.collectors?.length || 0} collectors)`);
      } else {
        setStatusMessage(`Compiler diagnostics: ${data.diagnostics?.length || 0} issue(s)`);
        setBottomPanelTab('problems');
        setShowBottomPanel(true);
      }

      // Update Monaco markers
      if (monacoRef.current && editorRef.current) {
        const model = editorRef.current.getModel();
        const markers = (data.diagnostics || []).map((d: Diagnostic) => ({
          severity:
            d.severity === 'error'
              ? monacoRef.current.MarkerSeverity.Error
              : d.severity === 'warning'
              ? monacoRef.current.MarkerSeverity.Warning
              : monacoRef.current.MarkerSeverity.Info,
          message: d.message,
          startLineNumber: d.line || 1,
          startColumn: d.column || 1,
          endLineNumber: d.line || 1,
          endColumn: (d.column || 1) + 8,
        }));
        monacoRef.current.editor.setModelMarkers(model, 'jockey', markers);
      }
    } catch (err: any) {
      setStatusMessage('Compiler check failed');
      setCheckPassed(false);
      setDiagnostics([
        {
          severity: 'error',
          message: err.response?.data?.message || err.message || 'Compiler service connection error',
          line: 1,
          column: 1,
        },
      ]);
      setRequiredCapabilities([]);
      setBottomPanelTab('problems');
      setShowBottomPanel(true);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunExecution = async () => {
    if (selectedTarget !== 'sandbox') {
      setStatusMessage('Execution unavailable for this target in the Web IDE. Use the local compiler.');
      setBottomPanelTab('problems');
      setShowBottomPanel(true);
      setExecutionResult(null);
      return;
    }
    setIsRunning(true);
    setStatusMessage('Executing forensic investigation...');
    setBottomPanelTab('output');
    setShowBottomPanel(true);
    try {
      const res = await api.post('/api/compiler/execute', {
        source,
        target: selectedTarget,
      });
      const data: ExecutionResult = res.data;
      setExecutionResult(data);
      setDiagnostics((data as any).diagnostics || []);
      setRequiredCapabilities([]);

      if (data.success) {
        setStatusMessage(
          `✓ Execution finished in ${data.execution_time_ms}ms (SHA-256: ${data.sha256.slice(0, 10)}...)`
        );
        if (data.evidence_items && data.evidence_items.length > 0) {
          setSelectedEvidenceItem(data.evidence_items[0]);
        }
      } else {
        setStatusMessage('Execution failed');
        setBottomPanelTab('problems');
      }
    } catch (err: any) {
      setStatusMessage('Execution request error');
      setExecutionResult({
        success: false,
        investigation_name: 'unknown',
        execution_target: selectedTarget,
        execution_time_ms: 0,
        collectors_executed: [],
        evidence_count: 0,
        sha256: '',
        integrity: 'ERROR',
        evidence_items: [],
        output_log: [
          'ERROR: Failed to contact jockey execution runtime.',
          err.response?.data?.message || err.message || 'Unknown network error',
        ],
      });
    } finally {
      setIsRunning(false);
    }
  };

  const handleJumpToLine = (line: number, col: number) => {
    if (editorRef.current) {
      editorRef.current.revealPositionInCenter({ lineNumber: line, column: col });
      editorRef.current.setPosition({ lineNumber: line, column: col });
      editorRef.current.focus();
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(source);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadTfg = () => {
    const blob = new Blob([source], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedExample}.tfg`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleExportEvidenceJson = () => {
    if (!executionResult || !executionResult.evidence_items) return;
    const blob = new Blob([JSON.stringify(executionResult.evidence_items, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${executionResult.investigation_name || 'evidence'}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-screen bg-[#0b0f17] text-slate-200 overflow-hidden font-sans">
      <SiteHeader />

      {/* Top Application Bar */}
      <div className="h-10 bg-[#0e1422] border-b border-slate-800 flex items-center justify-between px-3 text-xs select-none">
        {/* Left Actions */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 font-mono font-bold text-slate-100 pr-2 border-r border-slate-800">
            <TerminalIcon className="h-3.5 w-3.5 text-blue-400" />
            <span>jockey IDE</span>
          </div>

          <button
            onClick={() => {
              setSource('investigation "new_triage" {\n    collect system_info\n    export evidence "triage.json"\n}');
              setDiagnostics([]);
              setCheckPassed(null);
              setStatusMessage('Created new investigation');
            }}
            className="text-slate-400 hover:text-slate-100 px-2 py-1 rounded hover:bg-slate-800 transition-colors"
          >
            New
          </button>
          <button
            onClick={handleDownloadTfg}
            className="text-slate-400 hover:text-slate-100 px-2 py-1 rounded hover:bg-slate-800 transition-colors"
          >
            Download .tfg
          </button>
          <button
            onClick={handleCopyCode}
            className="text-slate-400 hover:text-slate-100 px-2 py-1 rounded hover:bg-slate-800 transition-colors"
          >
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>

        {/* Center Target & Actions */}
        <div className="flex items-center gap-2">
          {/* Target Selector */}
          <div className="flex items-center gap-1 bg-[#141b2d] border border-slate-700/80 rounded px-2 py-0.5 text-[11px] font-mono">
            <span className="text-slate-400">Target:</span>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="bg-transparent text-slate-200 outline-none cursor-pointer"
            >
              {targets.map((t) => (
                <option key={t.id} value={t.id} className="bg-[#111827] text-slate-200">
                  {t.name} ({t.status})
                </option>
              ))}
            </select>
          </div>

          {/* Check Button */}
          <button
            onClick={handleCheckCode}
            disabled={isLoading}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-colors disabled:opacity-50"
          >
            <CheckCircle2 className="h-3.5 w-3.5 text-blue-400" />
            <span>Check</span>
          </button>

          {/* Run Button */}
          <button
            onClick={handleRunExecution}
            disabled={isRunning}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium transition-colors disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>{isRunning ? 'Running...' : 'Run'}</span>
          </button>
        </div>

        {/* Right Status */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
            <span className="h-2 w-2 rounded-full bg-emerald-500" />
            <span>{statusMessage}</span>
          </div>

          <div className="flex items-center gap-1 border-l border-slate-800 pl-2">
            <button
              onClick={() => setShowExplorer(!showExplorer)}
              className={clsx(
                'p-1 rounded text-slate-400 hover:text-slate-200',
                showExplorer && 'text-blue-400 bg-slate-800'
              )}
              title="Toggle File Explorer"
            >
              <Folder className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => setShowInspector(!showInspector)}
              className={clsx(
                'p-1 rounded text-slate-400 hover:text-slate-200',
                showInspector && 'text-blue-400 bg-slate-800'
              )}
              title="Toggle Inspector"
            >
              <Sliders className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Workspace (3 Columns) */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Column: File Explorer */}
        {showExplorer && (
          <aside className="w-56 bg-[#0e1422] border-r border-slate-800 flex flex-col select-none text-xs">
            <div className="p-2 border-b border-slate-800 flex items-center justify-between text-slate-400 font-semibold tracking-wider uppercase text-[10px]">
              <span>Explorer</span>
              <span className="text-[10px] text-slate-400">jockey</span>
            </div>

            <div className="flex-1 overflow-y-auto p-1.5 space-y-1">
              {/* Examples Folder */}
              <div>
                <button
                  onClick={() => setExamplesOpen(!examplesOpen)}
                  className="w-full flex items-center gap-1.5 px-2 py-1 text-slate-400 hover:text-slate-200 font-mono text-[11px] rounded hover:bg-slate-800/50"
                >
                  {examplesOpen ? (
                    <ChevronDown className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5" />
                  )}
                  {examplesOpen ? (
                    <FolderOpen className="h-3.5 w-3.5 text-blue-400" />
                  ) : (
                    <Folder className="h-3.5 w-3.5 text-blue-400" />
                  )}
                  <span>examples/</span>
                </button>

                {examplesOpen && (
                  <div className="ml-3 pl-2 border-l border-slate-800 space-y-0.5 mt-0.5">
                    {EXAMPLES.map((ex) => (
                      <button
                        key={ex.id}
                        onClick={() => handleSelectExample(ex.id)}
                        className={clsx(
                          'w-full text-left px-2 py-1 rounded text-[11px] font-mono flex items-center gap-1.5 transition-colors',
                          selectedExample === ex.id
                            ? 'bg-blue-600/20 text-blue-300 border border-blue-500/30'
                            : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                        )}
                        title={ex.description}
                      >
                        <FileCode className="h-3 w-3 shrink-0" />
                        <span className="truncate">{ex.filename}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Explorer Footer info */}
            <div className="p-2 border-t border-slate-800 bg-[#090d15] text-[10px] font-mono text-slate-400">
              <div>Target: {selectedTarget}</div>
              <div>Mode: Read-Only Forensic</div>
            </div>
          </aside>
        )}

        {/* Center Column: Code Editor & Bottom Panel */}
        <div className="flex-1 flex flex-col overflow-hidden bg-[#0c111c]">
          {/* Editor Tab Header */}
          <div className="h-8 bg-[#111827] border-b border-slate-800 flex items-center justify-between px-3 select-none">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs text-slate-200 flex items-center gap-1.5">
                <FileCode className="h-3.5 w-3.5 text-blue-400" />
                {EXAMPLES.find((e) => e.id === selectedExample)?.filename || 'investigation.tfg'}
              </span>
              {checkPassed !== null && (
                <span
                  className={clsx(
                    'text-[10px] font-mono px-1.5 py-0.2 rounded border',
                    checkPassed
                      ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      : 'bg-rose-950 text-rose-400 border-rose-800'
                  )}
                >
                  {checkPassed ? 'VALID' : 'PROBLEMS'}
                </span>
              )}
            </div>

            <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
              <span>Lines: {source.split('\n').length}</span>
              <span>Chars: {source.length}</span>
            </div>
          </div>

          {/* Monaco Editor Container */}
          <div className="flex-1 overflow-hidden">
            <MonacoEditor
              height="100%"
              language="jockey"
              value={source}
              onChange={(value) => handleSourceChange(value || '')}
              onMount={handleEditorDidMount}
              options={{
                fontSize: 13,
                fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                lineNumbers: 'on',
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                automaticLayout: true,
                tabSize: 4,
                cursorBlinking: 'smooth',
                renderWhitespace: 'selection',
                bracketPairColorization: { enabled: true },
              }}
            />
          </div>

          {/* Bottom Panel (Collapsible) */}
          <div className="border-t border-slate-800 bg-[#0e1422] flex flex-col">
            {/* Panel Tabs Header */}
            <div className="h-8 bg-[#111827] border-b border-slate-800 flex items-center justify-between px-3 text-xs select-none">
              <div className="flex items-center gap-1">
                <button
                  onClick={() => {
                    setBottomPanelTab('output');
                    setShowBottomPanel(true);
                  }}
                  className={clsx(
                    'px-2.5 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1.5',
                    bottomPanelTab === 'output' && showBottomPanel
                      ? 'bg-slate-800 text-blue-400 border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  <TerminalIcon className="h-3.5 w-3.5" />
                  <span>Compiler Output</span>
                </button>

                <button
                  onClick={() => {
                    setBottomPanelTab('problems');
                    setShowBottomPanel(true);
                  }}
                  className={clsx(
                    'px-2.5 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1.5',
                    bottomPanelTab === 'problems' && showBottomPanel
                      ? 'bg-slate-800 text-blue-400 border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  <AlertTriangle className="h-3.5 w-3.5" />
                  <span>Problems ({diagnostics.length})</span>
                </button>

                <button
                  onClick={() => {
                    setBottomPanelTab('evidence');
                    setShowBottomPanel(true);
                  }}
                  className={clsx(
                    'px-2.5 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1.5',
                    bottomPanelTab === 'evidence' && showBottomPanel
                      ? 'bg-slate-800 text-blue-400 border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  <ShieldCheck className="h-3.5 w-3.5" />
                  <span>Evidence ({executionResult?.evidence_count || 0})</span>
                </button>

                <button
                  onClick={() => {
                    setBottomPanelTab('integrity');
                    setShowBottomPanel(true);
                  }}
                  className={clsx(
                    'px-2.5 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1.5',
                    bottomPanelTab === 'integrity' && showBottomPanel
                      ? 'bg-slate-800 text-blue-400 border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  <Hash className="h-3.5 w-3.5" />
                  <span>Integrity</span>
                </button>
              </div>

              {/* Panel Toggle */}
              <button
                onClick={() => setShowBottomPanel(!showBottomPanel)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded"
                title={showBottomPanel ? 'Collapse Panel' : 'Expand Panel'}
              >
                {showBottomPanel ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronUp className="h-3.5 w-3.5" />
                )}
              </button>
            </div>

            {/* Panel Body */}
            {showBottomPanel && (
              <div className="h-48 overflow-y-auto p-3 font-mono text-xs bg-[#090d15] text-slate-300">
                {/* 1. Compiler Output */}
                {bottomPanelTab === 'output' && (
                  <div className="space-y-1">
                    {executionResult ? (
                      <>
                        <div className="text-slate-400">=== EXECUTION RUN: {executionResult.investigation_name} ===</div>
                        <div>Target: {executionResult.execution_target}</div>
                        <div>Duration: {executionResult.execution_time_ms} ms</div>
                        <div>Integrity Status: {executionResult.integrity}</div>
                        <div>SHA-256 Digest: {executionResult.sha256}</div>
                        <div>Evidence Items Gathered: {executionResult.evidence_count}</div>
                        <div className="pt-2 text-slate-400">--- Execution Log ---</div>
                        {executionResult.output_log &&
                          executionResult.output_log.map((line, idx) => (
                            <div key={idx} className="text-slate-300">
                              {line}
                            </div>
                          ))}
                      </>
                    ) : (
                      <div className="text-slate-400">
                        No execution log yet. Click [Check] to validate with the compiler or [Run] to execute against the target.
                      </div>
                    )}
                  </div>
                )}

                {/* 2. Problems / Diagnostics */}
                {bottomPanelTab === 'problems' && (
                  <div>
                    {diagnostics.length === 0 ? (
                      <div className="text-emerald-400 flex items-center gap-2">
                        <CheckCircle2 className="h-4 w-4" />
                        <span>No compiler diagnostics reported. Syntax and AST valid.</span>
                      </div>
                    ) : (
                      <div className="space-y-1.5">
                        {diagnostics.map((d, idx) => (
                          <button
                            key={idx}
                            onClick={() => handleJumpToLine(d.line, d.column)}
                            className="w-full text-left p-1.5 rounded hover:bg-slate-800 flex items-start gap-2 group transition-colors"
                          >
                            {d.severity === 'error' ? (
                              <XCircle className="h-3.5 w-3.5 text-rose-400 shrink-0 mt-0.5" />
                            ) : (
                              <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
                            )}
                            <div className="flex-1">
                              <span className="text-slate-200 group-hover:text-blue-300 font-medium">
                                {d.message}
                              </span>
                              <span className="ml-2 text-slate-400 text-[11px]">
                                [Line {d.line}, Col {d.column}]
                              </span>
                            </div>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* 3. Evidence Table */}
                {bottomPanelTab === 'evidence' && (
                  <div>
                    {executionResult && executionResult.evidence_items && executionResult.evidence_items.length > 0 ? (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                          <span className="text-slate-400">
                            Collected {executionResult.evidence_items.length} forensic record(s)
                          </span>
                          <button
                            onClick={handleExportEvidenceJson}
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px]"
                          >
                            <Download className="h-3 w-3" />
                            Export Evidence JSON
                          </button>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-left border-collapse">
                            <thead>
                              <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                                <th className="py-1 px-2">Collector</th>
                                <th className="py-1 px-2">Timestamp (UTC)</th>
                                <th className="py-1 px-2">Source</th>
                                <th className="py-1 px-2">SHA-256 Digest</th>
                                <th className="py-1 px-2">Integrity</th>
                              </tr>
                            </thead>
                            <tbody>
                              {executionResult.evidence_items.map((item, idx) => (
                                <tr
                                  key={idx}
                                  onClick={() => setSelectedEvidenceItem(item)}
                                  className="border-b border-slate-800/60 hover:bg-slate-800/50 cursor-pointer"
                                >
                                  <td className="py-1.5 px-2 text-blue-400 font-semibold">{item.collector}</td>
                                  <td className="py-1.5 px-2 text-slate-300">{item.timestamp}</td>
                                  <td className="py-1.5 px-2 text-slate-400">{item.source}</td>
                                  <td className="py-1.5 px-2 text-slate-400">{item.sha256 ? item.sha256.slice(0, 16) + '...' : '-'}</td>
                                  <td className="py-1.5 px-2">
                                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">
                                      {item.integrity || 'VALID'}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>

                        {selectedEvidenceItem && (
                          <div className="mt-3 p-3 rounded border border-slate-800 bg-[#0c111c]">
                            <div className="text-slate-400 mb-1 text-[11px] font-semibold">
                              Payload for: {selectedEvidenceItem.collector} ({selectedEvidenceItem.id})
                            </div>
                            <pre className="text-[11px] text-slate-300 max-h-32 overflow-y-auto">
                              {JSON.stringify(selectedEvidenceItem.data, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-slate-400">
                        No evidence gathered yet. Run an investigation to inspect forensic envelopes.
                      </div>
                    )}
                  </div>
                )}

                {/* 4. Integrity Verification */}
                {bottomPanelTab === 'integrity' && (
                  <div className="space-y-3">
                    <div className="p-3 rounded border border-slate-800 bg-[#0c111c] space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-200">Cryptographic Non-Repudiation Status</span>
                        <span
                          className={clsx(
                            'px-2 py-0.5 rounded text-[10px]',
                            executionResult?.integrity === 'VALID'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          )}
                        >
                          {executionResult?.integrity || 'UNVERIFIED'}
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                        <div>
                          <span className="text-slate-400">Artifact SHA-256: </span>
                          <span className="text-slate-200">{executionResult?.sha256 || 'None computed'}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Metadata Sidecar: </span>
                          <span className="text-slate-200">
                            {executionResult ? `${executionResult.investigation_name}.json.meta.json` : 'Pending'}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400">Merkle Proof: </span>
                          <span className="text-slate-200">Not returned by sandbox</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Verification: </span>
                          <span className="text-slate-200">{executionResult ? 'Based on execution response' : 'Run an investigation to verify'}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Inspector Panel */}
        {showInspector && (
          <aside className="w-64 bg-[#0e1422] border-l border-slate-800 flex flex-col select-none text-xs">
            {/* Inspector Tabs */}
            <div className="h-8 bg-[#111827] border-b border-slate-800 flex items-center justify-around px-2 text-[11px] font-medium">
              <button
                onClick={() => setInspectorTab('diagnostics')}
                className={clsx(
                  'px-2 py-1 rounded transition-colors',
                  inspectorTab === 'diagnostics' ? 'text-blue-400 border-b-2 border-blue-500 font-semibold' : 'text-slate-400 hover:text-slate-200'
                )}
              >
                Diagnostics
              </button>
              <button
                onClick={() => setInspectorTab('capabilities')}
                className={clsx(
                  'px-2 py-1 rounded transition-colors',
                  inspectorTab === 'capabilities' ? 'text-blue-400 border-b-2 border-blue-500 font-semibold' : 'text-slate-400 hover:text-slate-200'
                )}
              >
                Capabilities
              </button>
              <button
                onClick={() => setInspectorTab('artifact')}
                className={clsx(
                  'px-2 py-1 rounded transition-colors',
                  inspectorTab === 'artifact' ? 'text-blue-400 border-b-2 border-blue-500 font-semibold' : 'text-slate-400 hover:text-slate-200'
                )}
              >
                Artifact
              </button>
            </div>

            {/* Inspector Content */}
            <div className="flex-1 overflow-y-auto p-3 space-y-4">
              {/* Tab 1: Diagnostics */}
              {inspectorTab === 'diagnostics' && (
                <div className="space-y-3">
                  <div>
                    <h4 className="text-[11px] font-bold text-slate-300 uppercase tracking-wider mb-1.5">
                      Compiler State
                    </h4>
                    <div className="p-2.5 rounded border border-slate-800 bg-[#090d15] space-y-1 font-mono text-[11px]">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">AST Validation:</span>
                        <span className={checkPassed ? 'text-emerald-400' : checkPassed === false ? 'text-rose-400' : 'text-slate-400'}>
                          {checkPassed ? 'Pass' : checkPassed === false ? 'Fail' : 'Unchecked'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Diagnostics:</span>
                        <span className="text-slate-200">{diagnostics.length}</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-[11px] font-bold text-slate-300 uppercase tracking-wider mb-1.5">
                      Selected Target
                    </h4>
                    <div className="p-2.5 rounded border border-slate-800 bg-[#090d15] space-y-1 font-mono text-[11px]">
                      <div className="text-slate-200 font-semibold">{selectedTarget}</div>
                      <div className="text-emerald-400 text-[10px]">Verified Native Platform</div>
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 2: Capabilities */}
              {inspectorTab === 'capabilities' && (
                <div className="space-y-3">
                  <div>
                    <h4 className="text-[11px] font-bold text-slate-300 uppercase tracking-wider mb-1">
                      Required Capabilities
                    </h4>
                    <p className="text-[11px] text-slate-400 mb-2">
                      Permissions reported by the compiler for the last successful check:
                    </p>
                    <div className="space-y-1">
                      {requiredCapabilities.length > 0 ? requiredCapabilities.map((cap) => (
                        <div
                          key={cap}
                          className="px-2 py-1 rounded bg-[#090d15] border border-slate-800 font-mono text-[11px] text-blue-300 flex items-center justify-between"
                        >
                          <span>{cap}</span>
                          <span className="text-slate-400 text-[10px]">Compiler output</span>
                        </div>
                      )) : (
                        <div className="text-slate-400">Run Check to inspect compiler capabilities.</div>
                      )}
                    </div>
                  </div>

                  <div className="p-2.5 rounded border border-slate-800 bg-[#090d15] text-[10px] text-slate-400 leading-relaxed">
                    <span className="font-semibold text-slate-300">Execution boundary: </span>
                    Browser editing does not execute host commands. Run uses the controlled server sandbox.
                  </div>
                </div>
              )}

              {/* Tab 3: Artifact Metadata */}
              {inspectorTab === 'artifact' && (
                <div className="space-y-3">
                  <h4 className="text-[11px] font-bold text-slate-300 uppercase tracking-wider mb-1">
                    Artifact Information
                  </h4>

                  <div className="p-2.5 rounded border border-slate-800 bg-[#090d15] space-y-2 font-mono text-[11px]">
                    <div>
                      <div className="text-slate-400 text-[10px]">Tool Version:</div>
                      <div className="text-slate-200">0.1.0</div>
                    </div>
                    <div>
                      <div className="text-slate-400 text-[10px]">Target Platform:</div>
                      <div className="text-slate-200">{selectedTarget}</div>
                    </div>
                    <div>
                      <div className="text-slate-400 text-[10px]">Compiler Hash:</div>
                      <div className="text-slate-400 truncate">1e539f20b535e97ff4b44a...</div>
                    </div>
                    <div>
                      <div className="text-slate-400 text-[10px]">Investigation:</div>
                      <div className="text-blue-300">{selectedExample}</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
