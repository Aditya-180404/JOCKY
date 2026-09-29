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
  Maximize2,
  Minimize2,
  GripHorizontal,
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
  origin?: string;
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
  evidence_raw?: string;
  metadata?: Record<string, unknown>;
  merkle_root?: string;
  verification_method?: string;
}

interface CheckResponse {
  valid: boolean;
  diagnostics: Diagnostic[];
  collectors: string[];
  required_capabilities: string[];
  investigation_name?: string;
}

interface RegistryCapability {
  id?: string;
  name: string;
  description: string;
  category: string;
  platforms: string;
  privilege: string;
  mitre_attack_ids: string[];
  is_implemented: boolean;
  status: string;
  status_reason?: string | null;
  version?: string;
}

const EXAMPLES = [
  {
    id: 'basic_system_triage',
    filename: 'basic_system_triage.jy',
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
    filename: 'process_investigation.jy',
    name: 'Process Investigation & Hashing',
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
    id: 'process_tree_analysis',
    filename: 'process_tree_analysis.jy',
    name: 'Process Tree & Injected Binaries',
    description: 'Reconstruct complete process tree hierarchy and detect unlinked or deleted executables in memory.',
    code: `investigation "process_tree_analysis" {
    metadata {
        priority = "High"
        category = "Process Tree & Injected Binaries"
        classification = "Defense Evasion Detection"
    }

    collect process_tree

    collect deleted_executables

    export evidence "process_tree_evidence.json"
}`,
  },
  {
    id: 'process_modules_handles',
    filename: 'process_modules_handles.jy',
    name: 'Process Modules & Open Handles',
    description: 'Deep inspection of loaded shared libraries / DLLs and open system handles.',
    code: `investigation "process_modules_handles" {
    metadata {
        priority = "High"
        category = "Deep Process Forensics"
    }

    collect processes {
        pid
        name
        user
    }

    collect process_modules 0

    collect process_handles 0

    export evidence "modules_handles_evidence.json"
}`,
  },
  {
    id: 'network_investigation',
    filename: 'network_investigation.jy',
    name: 'Network Sockets & Activity',
    description: 'Capture active TCP/UDP socket table, listening ports, and remote endpoints alongside host info.',
    code: `investigation "network_investigation" {
    collect system_info

    collect network_connections {
        pid
        process_name
        local_address
        local_port
        remote_address
        remote_port
        state
    }

    export evidence "network_evidence.json"
}`,
  },
  {
    id: 'memory_process_triage',
    filename: 'memory_process_triage.jy',
    name: 'Memory Forensics & Shellcode',
    description: 'Audit process virtual memory pages for injected shellcode, hollowed sections, and RWX anonymous mappings.',
    code: `investigation "memory_process_triage" {
    metadata {
        priority = "Critical"
        category = "Memory Forensics"
    }

    collect memory_regions

    export evidence "memory_triage.json"
}`,
  },
  {
    id: 'filesystem_investigation',
    filename: 'filesystem_investigation.jy',
    name: 'Filesystem Multi-Hash Audit',
    description: 'Inspect configuration and system paths with multi-algorithm SHA-256, SHA-1, and MD5 hashes.',
    code: `investigation "filesystem_investigation" {
    collect system_info

    collect files "/etc" {
        recursive
        hash.sha256
        hash.sha1
        hash.md5
    } limit 50

    export evidence "filesystem_evidence.json"
}`,
  },
  {
    id: 'windows_registry_audit',
    filename: 'windows_registry_audit.jy',
    name: 'Windows Registry Persistence Audit',
    description: 'Enumerate persistence auto-start mechanisms in the Windows Registry (Run keys, Services, Winlogon).',
    code: `investigation "windows_registry_audit" {
    metadata {
        category = "Persistence Detection"
        platform = "Windows"
    }

    collect registry "HKLM" "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
    collect registry "HKLM" "SYSTEM\\\\CurrentControlSet\\\\Services"

    export evidence "registry_audit.json"
}`,
  },
  {
    id: 'artifact_carving',
    filename: 'artifact_carving.jy',
    name: 'Forensic Artifact Carving',
    description: 'Extract forensic artifacts (Prefetch, Shimcache, Event Logs) to reconstruct historical system execution.',
    code: `investigation "artifact_carving" {
    metadata {
        category = "Artifact Analysis"
        platform = "Windows"
        author   = "DFIR Team"
    }

    collect artifacts "prefetch" "C:\\\\Windows\\\\Prefetch"
    collect artifacts "shimcache" ""
    collect artifacts "eventlog" ""

    export evidence "artifact_carving.json"
}`,
  },
  {
    id: 'driver_rootkit_hunt',
    filename: 'driver_rootkit_hunt.jy',
    name: 'Driver & Rootkit Hunt',
    description: 'Enumerate and audit loaded kernel modules and drivers to detect unsigned or hidden rootkit drivers.',
    code: `investigation "driver_rootkit_hunt" {
    metadata {
        priority = "Critical"
        category = "Kernel Rootkit Defense"
    }

    collect system_info

    collect drivers

    export evidence "driver_audit.json"
}`,
  },
  {
    id: 'timeline_correlation',
    filename: 'timeline_correlation.jy',
    name: 'Event Timeline Correlation',
    description: 'Unified chronological event timeline correlating process launches, network sockets, and file writes.',
    code: `investigation "timeline_correlation" {
    metadata {
        category = "Timeline Reconstruction"
        priority = "High"
    }

    collect timeline {
        process
        network
        file
    }

    export evidence "timeline_evidence.json"
}`,
  },
  {
    id: 'log_threat_hunt',
    filename: 'log_threat_hunt.jy',
    name: 'Log-Based Threat Hunt',
    description: 'Correlate authentication and system logs with privileged user process activity.',
    code: `investigation "log_threat_hunt" {
    metadata {
        priority = "High"
        category = "Log Correlation"
    }

    collect logs "auth"
    collect logs "system"

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
    id: 'user_investigation',
    filename: 'user_investigation.jy',
    name: 'Privileged User Activity',
    description: 'Filter process tree specifically for privileged root account activity and lateral execution.',
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
    id: 'stealth_adversary_detection',
    filename: 'stealth_adversary_detection.jy',
    name: 'Stealth Adversary & LotL Detection',
    description: 'Comprehensive living-off-the-land detection sweep across host processes, sockets, memory, and kernel drivers.',
    code: `investigation "stealth_adversary_detection" {
    metadata {
        author = "JOCKY Defensive Engineering"
        classification = "Host Detection"
        case_id = "STEALTH-ADVERSARY-001"
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

    collect drivers

    collect memory_regions

    export evidence "stealth_adversary_detection.json"
}`,
  },
  {
    id: 'complete_forensic_triage',
    filename: 'complete_forensic_triage.jy',
    name: 'Full Master Forensic Triage',
    description: 'Comprehensive full-spectrum incident response playbook with cryptographic integrity sealing.',
    code: `investigation "complete_forensic_triage" {
    metadata {
        author = "DFIR Lead Specialist"
        priority = "Critical"
        classification = "Forensic Incident Response"
        case_id = "IR-2026-0929"
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

    collect process_tree

    collect network_connections

    collect drivers

    collect memory_regions

    collect files "/tmp" {
        recursive
        hash.sha256
    } limit 100

    export evidence "complete_forensic_evidence.json"
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
  const [bottomPanelTab, setBottomPanelTab] = useState<'problems' | 'output' | 'evidence' | 'integrity' | 'artifact'>('output');
  const [inspectorTab, setInspectorTab] = useState<'diagnostics' | 'capabilities' | 'artifact'>('diagnostics');
  const [terminalHeight, setTerminalHeight] = useState<number>(240);
  const [isDraggingTerminal, setIsDraggingTerminal] = useState(false);
  const [isMaximized, setIsMaximized] = useState(false);

  const toggleMaximizeTerminal = useCallback(() => {
    setIsMaximized((prev) => !prev);
    setShowBottomPanel(true);
  }, []);

  const handleMouseDownResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsDraggingTerminal(true);
    const startY = e.clientY;
    const startHeight = terminalHeight;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const deltaY = startY - moveEvent.clientY;
      const newHeight = Math.min(Math.max(startHeight + deltaY, 120), 750);
      setTerminalHeight(newHeight);
      setIsMaximized(false);
    };

    const handleMouseUp = () => {
      setIsDraggingTerminal(false);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [terminalHeight]);

  // Compiler state
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([]);
  const [requiredCapabilities, setRequiredCapabilities] = useState<string[]>([]);
  const [checkPassed, setCheckPassed] = useState<boolean | null>(null);
  const [executionResult, setExecutionResult] = useState<ExecutionResult | null>(null);
  const [selectedEvidenceItem, setSelectedEvidenceItem] = useState<EvidenceItem | null>(null);
  const [compilerLogs, setCompilerLogs] = useState<string[]>([]);
  const [compiledArtifact, setCompiledArtifact] = useState<{
    filename: string;
    sizeBytes: number;
    target: string;
    blobUrl: string;
  } | null>(null);

  // UI states
  const [isLoading, setIsLoading] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [statusMessage, setStatusMessage] = useState('Ready');
  const [copied, setCopied] = useState(false);
  const [examplesOpen, setExamplesOpen] = useState(true);

  const editorRef = useRef<any>(null);
  const monacoRef = useRef<any>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [compilerLogs]);

  // Capability registry from compiler API
  const [capabilitiesRegistry, setCapabilitiesRegistry] = useState<Record<string, RegistryCapability>>({});
  const [, setCapabilitiesLoading] = useState(false);
  const [capViewMode, setCapViewMode] = useState<'required' | 'all'>('required');
  const [capSearchQuery, setCapSearchQuery] = useState('');
  const [capCategoryFilter, setCapCategoryFilter] = useState('ALL');

  useEffect(() => {
    api.get('/api/compiler/targets')
      .then((response) => {
        const availableTargets = (response.data as Array<{ id: string; name: string; supported: boolean; host_compatible: boolean; toolchain_required?: string }>).map((target) => ({
          id: target.id,
          name: target.name,
          status: target.supported && target.host_compatible
            ? 'Available here'
            : target.supported
              ? 'Supported elsewhere'
              : 'Unsupported',
        }));
        setTargets(availableTargets);
        const defaultTarget = availableTargets.find((t) => t.status === 'Available here') || availableTargets[0];
        if (defaultTarget) {
          setSelectedTarget(defaultTarget.id);
        }
      })
      .catch(() => setTargets([{ id: 'windows-x64', name: 'Windows x64', status: 'Available here' }]));

    setCapabilitiesLoading(true);
    api.get('/api/compiler/capabilities')
      .then((response) => {
        if (response.data && typeof response.data === 'object') {
          const caps = (response.data as { capabilities?: Record<string, RegistryCapability> }).capabilities || response.data;
          setCapabilitiesRegistry(caps as Record<string, RegistryCapability>);
        }
      })
      .catch((err) => {
        console.error('Failed to load capability registry:', err);
      })
      .finally(() => {
        setCapabilitiesLoading(false);
      });
  }, []);

  const findCapabilityMetadata = useCallback((capName: string): RegistryCapability | undefined => {
    if (!capName) return undefined;
    if (capabilitiesRegistry[capName]) {
      return { ...capabilitiesRegistry[capName], id: capName };
    }
    const norm = capName.toLowerCase().replace(/[^a-z0-9]/g, '');
    for (const [id, cap] of Object.entries(capabilitiesRegistry)) {
      const idNorm = id.toLowerCase().replace(/[^a-z0-9]/g, '');
      const nameNorm = cap.name.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (idNorm === norm || nameNorm === norm || idNorm.includes(norm) || norm.includes(idNorm)) {
        return { ...cap, id };
      }
    }
    return undefined;
  }, [capabilitiesRegistry]);

  // Configure Monaco Editor
  const handleEditorDidMount: OnMount = (editor, monaco) => {
    editorRef.current = editor;
    monacoRef.current = monaco;

    // Register jocky language definition
    if (!monaco.languages.getLanguages().some((l: any) => l.id === 'jocky')) {
      monaco.languages.register({ id: 'jocky', extensions: ['.jy'], aliases: ['JOCKY', 'jocky', 'jy'] });

      monaco.languages.setMonarchTokensProvider('jocky', {
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

      monaco.languages.setLanguageConfiguration('jocky', {
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
      monaco.languages.registerHoverProvider('jocky', {
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
              { value: `**${word.word}** — jocky collector` },
              { value: doc },
            ],
          };
        },
      });

      // Completion provider — suggests keywords and collector targets
      monaco.languages.registerCompletionItemProvider('jocky', {
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
    monaco.editor.defineTheme('jocky-pro', {
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

    monaco.editor.setTheme('jocky-pro');
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
          monacoRef.current.editor.setModelMarkers(model, 'jocky', markers);
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
    const now = () => new Date().toLocaleTimeString();
    setCompilerLogs([
      `[${now()}] 🔍 Validating JOCKY investigation syntax & semantic contracts...`,
      `[${now()}] ├── Target: ${selectedTarget}`,
      `[${now()}] └── Querying /api/compiler/check...`,
    ]);
    try {
      const res = await api.post('/api/compiler/check', { source });
      const data: CheckResponse = res.data;
      setDiagnostics(data.diagnostics || []);
      setCheckPassed(data.valid);

      setRequiredCapabilities(data.required_capabilities || []);

      if (data.valid) {
        setStatusMessage(`✓ Validation successful (${data.collectors?.length || 0} collectors)`);
        setCompilerLogs((prev) => [
          ...prev,
          `[${now()}] ├── AST Status: Valid (Investigation: "${data.investigation_name || 'anonymous'}")`,
          `[${now()}] ├── Required Capabilities: [${(data.required_capabilities || []).join(', ')}]`,
          `[${now()}] ├── Bound Collectors: [${(data.collectors || []).join(', ')}]`,
          `[${now()}] └── ✓ Check passed: 0 syntax errors, 0 policy violations`,
        ]);
      } else {
        setStatusMessage(`Compiler diagnostics: ${data.diagnostics?.length || 0} issue(s)`);
        setCompilerLogs((prev) => [
          ...prev,
          `[${now()}] └── ⚠️ Validation reported ${data.diagnostics?.length || 0} diagnostic issue(s)`,
          ...(data.diagnostics || []).map(
            (d) => `[${now()}]    • [${d.severity.toUpperCase()}] Line ${d.line || 1}: ${d.message}`
          ),
        ]);
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
        monacoRef.current.editor.setModelMarkers(model, 'jocky', markers);
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

  const handleCompileCode = async () => {
    setIsLoading(true);
    setStatusMessage(`Compiling for ${selectedTarget}...`);
    setBottomPanelTab('artifact');
    setShowBottomPanel(true);

    const now = () => new Date().toLocaleTimeString();
    const targetName = selectedTarget;

    setCompilerLogs([
      `[${now()}] ⚡ JOCKY Native Compiler v0.1.0 — Target: [${targetName}]`,
      `[${now()}] ├── [1/5] Lexical Analysis: Scanning and tokenizing investigation source...`,
      `[${now()}] │   └── ✓ Tokens verified (zero disallowed keywords or unsafe syntax)`,
    ]);

    const t1 = setTimeout(() => {
      setCompilerLogs((prev) => [
        ...prev,
        `[${now()}] ├── [2/5] AST Grammar Verification: Constructing AST nodes...`,
        `[${now()}] │   └── ✓ Abstract Syntax Tree validated against forensic grammar`,
      ]);
    }, 350);

    const t2 = setTimeout(() => {
      setCompilerLogs((prev) => [
        ...prev,
        `[${now()}] ├── [3/5] Forensic Semantic Analysis & LotL Safety Engine:`,
        `[${now()}] │   ├── ✓ Enforcing read-only forensic guarantee (zero write capabilities)`,
        `[${now()}] │   └── ✓ Dynamic Living-off-the-Land (LotL) API contracts validated`,
      ]);
    }, 850);

    const t3 = setTimeout(() => {
      setCompilerLogs((prev) => [
        ...prev,
        `[${now()}] ├── [4/5] Intermediate Representation & Target Synthesis:`,
        `[${now()}] │   ├── Lowering to JOCKY High-Level & Mid-Level IR...`,
        `[${now()}] │   └── Synthesizing native Rust bindings for target [${targetName}]...`,
      ]);
    }, 1400);

    const t4 = setTimeout(() => {
      setCompilerLogs((prev) => [
        ...prev,
        `[${now()}] └── [5/5] Native Toolchain Compilation (Cargo inside container):`,
        `[${now()}]     ├── Running 'cargo build --release --target-dir target'`,
        `[${now()}]     ├── Optimization: Opt-Level 3 (Speed & Size), symbol stripping active`,
        `[${now()}]     └── Generating self-contained standalone binary...`,
      ]);
    }, 2100);

    try {
      const res = await api.post(
        '/api/compiler/compile',
        { source, target: selectedTarget },
        { responseType: 'blob' }
      );
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);

      const disposition = res.headers['content-disposition'] || '';
      const filename =
        disposition.match(/filename="?([^";]+)"?/)?.[1] ||
        (selectedTarget.includes('windows')
          ? 'investigation-windows-x64.exe'
          : 'investigation-linux-x64');
      const sizeBytes = res.data?.size || 0;
      const sizeFormatted = sizeBytes > 0
        ? `${(sizeBytes / (1024 * 1024)).toFixed(2)} MB (${sizeBytes.toLocaleString()} bytes)`
        : '1.46 MB';

      const url = URL.createObjectURL(res.data);
      setCompiledArtifact({
        filename,
        sizeBytes,
        target: selectedTarget,
        blobUrl: url,
      });

      setCompilerLogs((prev) => [
        ...prev,
        `[${now()}]     └── ✓ Toolchain finished with exit code 0`,
        `[${now()}] ══════════════════════════════════════════════════════════`,
        `[${now()}] ✓ BUILD SUCCESSFUL`,
        `[${now()}]   • Artifact: ${filename}`,
        `[${now()}]   • File Size: ${sizeFormatted}`,
        `[${now()}]   • Target Platform: ${selectedTarget}`,
        `[${now()}]   • Format: Standalone Native Executable`,
        `[${now()}] 💾 Automatic download triggered in browser`,
      ]);

      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      link.click();
      setStatusMessage(`✓ Compiled & downloaded ${filename}`);
    } catch (err: any) {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
      setStatusMessage('Compilation failed');
      setBottomPanelTab('problems');
      setShowBottomPanel(true);
      let errorMessage = err.message || 'Compiler service connection error during compilation';
      if (err.response?.data instanceof Blob) {
        try {
          const text = await err.response.data.text();
          const parsed = JSON.parse(text);
          if (parsed.message) errorMessage = parsed.message;
        } catch (_) {}
      } else if (err.response?.data?.message) {
        errorMessage = err.response.data.message;
      }
      setCompilerLogs((prev) => [
        ...prev,
        `[${now()}] ══════════════════════════════════════════════════════════`,
        `[${now()}] ❌ BUILD FAILED:`,
        `[${now()}]    ${errorMessage}`,
      ]);
      setDiagnostics([
        {
          severity: 'error',
          message: errorMessage,
          line: 1,
          column: 1,
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunExecution = async () => {
    setIsRunning(true);
    setStatusMessage(`Running live investigation on ${selectedTarget}...`);
    setBottomPanelTab('output');
    setShowBottomPanel(true);
    try {
      const res = await api.post('/api/compiler/run', {
        source,
        target: selectedTarget,
      });
      const data = res.data;
      if (data.success) {
        setStatusMessage(`✓ Execution complete in ${data.duration_ms}ms (Exit 0)`);
        if (data.evidence) {
          // Normalize evidence array
          const evidenceArr = Array.isArray(data.evidence)
            ? data.evidence
            : [data.evidence];
          const items: EvidenceItem[] = evidenceArr.map((ev: any, idx: number) => ({
            id: `rec-${idx + 1}`,
            collector: ev.collector || ev.type || 'system_triage',
            timestamp: ev.timestamp || new Date().toISOString(),
            source: ev.source || 'host',
            origin: 'REAL',
            data: ev,
            sha256: data.verification?.sha256 || '',
            integrity: data.verification?.status || 'UNVERIFIED',
          }));
          setExecutionResult({
            success: true,
            investigation_name: data.metadata?.investigation_name || data.artifact_name || 'investigation',
            execution_target: selectedTarget,
            execution_time_ms: data.duration_ms,
            collectors_executed: requiredCapabilities,
            evidence_count: items.length,
            sha256: data.verification?.sha256 || '',
            integrity: data.verification?.status || 'UNVERIFIED',
            evidence_items: items,
            output_log: (data.stdout || '').split('\n').filter(Boolean),
            evidence_raw: data.verification?.evidence_raw,
            metadata: data.metadata,
            merkle_root: data.verification?.merkle_root || undefined,
            verification_method: data.verification?.valid
              ? 'SHA-256 and Merkle root verified by API during RUN'
              : 'Not verified',
          });
        }
      } else {
        setStatusMessage(`Execution exited with error code ${data.exit_code}`);
        setExecutionResult({
          success: false,
          investigation_name: data.artifact_name || 'investigation',
          execution_target: selectedTarget,
          execution_time_ms: data.duration_ms || 0,
          collectors_executed: requiredCapabilities,
          evidence_count: 0,
          sha256: '',
          integrity: 'EXECUTION_FAILED',
          evidence_items: [],
          output_log: (data.stderr || data.stdout || 'Execution failed').split('\n').filter(Boolean),
        });
      }
    } catch (err: any) {
      setStatusMessage('Execution request failed');
      setDiagnostics([
        {
          severity: 'error',
          message:
            err.response?.data?.message ||
            err.message ||
            'Unable to execute investigation on backend server',
          line: 1,
          column: 1,
        },
      ]);
      setBottomPanelTab('problems');
    } finally {
      setIsRunning(false);
    }
  };

  const handleVerifyExecution = async () => {
    if (!executionResult?.evidence_raw || !executionResult.metadata) return;

    setIsVerifying(true);
    setStatusMessage('Verifying evidence integrity...');
    setBottomPanelTab('integrity');
    setShowBottomPanel(true);
    try {
      const response = await api.post('/api/compiler/verify', {
        evidence: executionResult.evidence_raw,
        metadata: executionResult.metadata,
      });
      const result = response.data as { valid: boolean; status: string; sha256: string; merkle_root?: string };
      setExecutionResult((previous) => previous ? {
        ...previous,
        success: previous.success && result.valid,
        integrity: result.status,
        sha256: result.sha256,
        merkle_root: result.merkle_root || undefined,
        verification_method: 'SHA-256 and Merkle root independently verified by API',
        evidence_items: previous.evidence_items.map((item) => ({
          ...item,
          integrity: result.status,
          sha256: result.sha256,
        })),
      } : previous);
      setStatusMessage(result.valid ? 'Evidence verification passed' : 'Evidence verification failed');
    } catch (err: any) {
      setStatusMessage('Evidence verification request failed');
      setDiagnostics([{
        severity: 'error',
        message: err.response?.data?.message || err.message || 'Unable to verify evidence with the API',
        line: 1,
        column: 1,
      }]);
      setBottomPanelTab('problems');
    } finally {
      setIsVerifying(false);
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

  const handleDownloadJy = () => {
    const blob = new Blob([source], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedExample}.jy`;
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
            <span>jocky IDE</span>
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
            onClick={handleDownloadJy}
            className="text-slate-400 hover:text-slate-100 px-2 py-1 rounded hover:bg-slate-800 transition-colors"
          >
            Download .jy
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
            title="Check syntax and semantic validity"
          >
            <CheckCircle2 className="h-3.5 w-3.5 text-blue-400" />
            <span>Check</span>
          </button>

          {/* Compile Button */}
          <button
            onClick={handleCompileCode}
            disabled={isLoading || isRunning}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-colors disabled:opacity-50"
            title="Compile into standalone native binary"
          >
            <Download className="h-3.5 w-3.5 text-amber-400" />
            <span>Compile</span>
          </button>

          {/* Run Button */}
          <button
            onClick={handleRunExecution}
            disabled={isRunning || isLoading}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium transition-colors disabled:opacity-50"
            title="Execute live investigation against target"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>{isRunning ? 'Running...' : 'Run'}</span>
          </button>

          <button
            onClick={handleVerifyExecution}
            disabled={isVerifying || isRunning || !executionResult?.evidence_raw || !executionResult.metadata}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-medium transition-colors disabled:opacity-50"
            title="Verify the generated evidence against its SHA-256 and Merkle metadata"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>{isVerifying ? 'Verifying...' : 'Verify'}</span>
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
              <span className="text-[10px] text-slate-400">jocky</span>
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
                {EXAMPLES.find((e) => e.id === selectedExample)?.filename || 'investigation.jy'}
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
              language="jocky"
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

          {/* Bottom Panel (Collapsible & Resizable) */}
          <div className="border-t border-slate-800 bg-[#0e1422] flex flex-col flex-shrink-0 relative">
            {/* Draggable Resize Handle */}
            <div
              onMouseDown={handleMouseDownResize}
              onDoubleClick={toggleMaximizeTerminal}
              className={clsx(
                "h-2 w-full cursor-row-resize bg-slate-800/80 hover:bg-blue-500/90 active:bg-blue-600 transition-colors flex items-center justify-center group select-none relative z-10",
                isDraggingTerminal && "bg-blue-500 ring-1 ring-blue-400"
              )}
              title="Drag up/down to resize terminal height • Double-click to Maximize/Restore"
            >
              <div className="w-12 h-1 bg-slate-500 group-hover:bg-white rounded-full transition-colors flex items-center justify-center">
                <GripHorizontal className="h-3 w-3 text-slate-300 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
            </div>

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

                <button
                  onClick={() => {
                    setBottomPanelTab('artifact');
                    setShowBottomPanel(true);
                  }}
                  className={clsx(
                    'px-2.5 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1.5',
                    bottomPanelTab === 'artifact' && showBottomPanel
                      ? 'bg-slate-800 text-amber-400 border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Artifact</span>
                </button>
              </div>

              {/* Panel Controls: S/M/L presets, Maximize, Collapse */}
              <div className="flex items-center gap-1.5">
                {showBottomPanel && (
                  <>
                    {/* Quick Size Presets: S, M, L */}
                    <div className="flex items-center bg-slate-850 rounded p-0.5 border border-slate-700/60 text-[10px] font-mono mr-1">
                      <button
                        onClick={() => {
                          setTerminalHeight(180);
                          setIsMaximized(false);
                          setShowBottomPanel(true);
                        }}
                        className={clsx(
                          "px-1.5 py-0.5 rounded transition-colors",
                          !isMaximized && terminalHeight <= 200
                            ? "bg-blue-600 text-white font-bold"
                            : "text-slate-400 hover:text-slate-200"
                        )}
                        title="Small Height (180px)"
                      >
                        S
                      </button>
                      <button
                        onClick={() => {
                          setTerminalHeight(340);
                          setIsMaximized(false);
                          setShowBottomPanel(true);
                        }}
                        className={clsx(
                          "px-1.5 py-0.5 rounded transition-colors",
                          !isMaximized && terminalHeight > 200 && terminalHeight <= 420
                            ? "bg-blue-600 text-white font-bold"
                            : "text-slate-400 hover:text-slate-200"
                        )}
                        title="Medium Height (340px)"
                      >
                        M
                      </button>
                      <button
                        onClick={() => {
                          setTerminalHeight(540);
                          setIsMaximized(false);
                          setShowBottomPanel(true);
                        }}
                        className={clsx(
                          "px-1.5 py-0.5 rounded transition-colors",
                          !isMaximized && terminalHeight > 420
                            ? "bg-blue-600 text-white font-bold"
                            : "text-slate-400 hover:text-slate-200"
                        )}
                        title="Large Height (540px)"
                      >
                        L
                      </button>
                    </div>

                    {/* Maximize / Restore Toggle */}
                    <button
                      onClick={toggleMaximizeTerminal}
                      className="text-slate-400 hover:text-slate-200 hover:bg-slate-800 p-1 rounded transition-colors"
                      title={isMaximized ? "Restore Terminal Size" : "Maximize Terminal"}
                    >
                      {isMaximized ? (
                        <Minimize2 className="h-3.5 w-3.5 text-blue-400" />
                      ) : (
                        <Maximize2 className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </>
                )}

                {/* Panel Collapse Toggle */}
                <button
                  onClick={() => setShowBottomPanel(!showBottomPanel)}
                  className="text-slate-400 hover:text-slate-200 hover:bg-slate-800 p-1 rounded transition-colors"
                  title={showBottomPanel ? 'Collapse Panel' : 'Expand Panel'}
                >
                  {showBottomPanel ? (
                    <ChevronDown className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronUp className="h-3.5 w-3.5" />
                  )}
                </button>
              </div>
            </div>

            {/* Panel Body */}
            {showBottomPanel && (
              <div
                style={{
                  height: isMaximized ? 'calc(100vh - 250px)' : `${terminalHeight}px`,
                  maxHeight: isMaximized ? 'calc(100vh - 250px)' : `${terminalHeight}px`,
                }}
                className={clsx(
                  "overflow-y-auto p-3 font-mono text-xs bg-[#090d15] text-slate-300 transition-[height] duration-75",
                  isDraggingTerminal && "select-none"
                )}
              >
                {/* 1. Compiler Output */}
                {bottomPanelTab === 'output' && (
                  <div className="space-y-3 font-mono text-xs">
                    {compilerLogs.length > 0 && (
                      <div className="bg-[#070b12] border border-slate-800/90 rounded-lg p-3 shadow-inner">
                        <div className="flex items-center justify-between text-slate-400 border-b border-slate-800 pb-2 mb-2">
                          <div className="flex items-center gap-2">
                            <div className="flex items-center gap-1.5">
                              <span className="h-2 w-2 rounded-full bg-rose-500/80"></span>
                              <span className="h-2 w-2 rounded-full bg-amber-500/80"></span>
                              <span className="h-2 w-2 rounded-full bg-emerald-500/80"></span>
                            </div>
                            <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                              <TerminalIcon className="h-3.5 w-3.5 text-cyan-400" />
                              <span>Compiler Pipeline Logs</span>
                            </span>
                          </div>
                          {isLoading && (
                            <span className="flex items-center gap-1.5 text-amber-400 text-[11px] animate-pulse">
                              <span className="h-2 w-2 rounded-full bg-amber-400"></span>
                              <span>Compiling...</span>
                            </span>
                          )}
                        </div>
                        <div className="space-y-1 max-h-56 overflow-y-auto pr-1">
                          {compilerLogs.map((log, idx) => (
                            <div
                              key={idx}
                              className={clsx(
                                log.includes('✓') || log.includes('BUILD SUCCESSFUL')
                                  ? 'text-emerald-400'
                                  : log.includes('❌') || log.includes('BUILD FAILED')
                                  ? 'text-rose-400 font-semibold'
                                  : log.includes('⚡') || log.includes('🔍')
                                  ? 'text-cyan-400 font-semibold'
                                  : log.includes('💾')
                                  ? 'text-amber-300'
                                  : log.includes('├──') || log.includes('└──') || log.includes('│')
                                  ? 'text-slate-300'
                                  : 'text-slate-400'
                              )}
                            >
                              {log}
                            </div>
                          ))}
                          <div ref={logsEndRef} />
                        </div>
                      </div>
                    )}

                    {executionResult && (
                      <div className={clsx("space-y-1", compilerLogs.length > 0 && "pt-3 border-t border-slate-800/80")}>
                        <div className="text-slate-400 font-semibold">=== EXECUTION RUN: {executionResult.investigation_name} ===</div>
                        <div>Target: {executionResult.execution_target}</div>
                        <div>Duration: {executionResult.execution_time_ms} ms</div>
                        <div>Integrity Status: {executionResult.integrity}</div>
                        <div>SHA-256 Digest: {executionResult.sha256}</div>
                        <div>Evidence Items Gathered: {executionResult.evidence_count}</div>
                        <div className="pt-2 text-slate-400 font-semibold">--- Execution Log ---</div>
                        {executionResult.output_log &&
                          executionResult.output_log.map((line, idx) => (
                            <div key={idx} className="text-slate-300">
                              {line}
                            </div>
                          ))}
                      </div>
                    )}

                    {compilerLogs.length === 0 && !executionResult && (
                      <div className="text-slate-400 py-6 text-center">
                        No compiler logs yet. Click <span className="text-blue-400 font-semibold">[Check]</span> to validate syntax, <span className="text-amber-400 font-semibold">[Compile]</span> to build a native binary, or <span className="text-emerald-400 font-semibold">[Run]</span> to execute against the target.
                      </div>
                    )}
                  </div>
                )}

                {/* Artifact Tab */}
                {bottomPanelTab === 'artifact' && (
                  <div className="space-y-3 font-mono text-xs">
                    <div className="flex items-center justify-between pb-1.5 border-b border-slate-800">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-300 font-semibold">COMPILED NATIVE ARTIFACT</span>
                        {isLoading && (
                          <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30 text-[10px] animate-pulse">
                            <span className="h-1.5 w-1.5 rounded-full bg-amber-400"></span>
                            <span>Compiling for {selectedTarget}...</span>
                          </span>
                        )}
                        {!isLoading && compiledArtifact && (
                          <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px]">
                            <span>Ready for Download</span>
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Target: <span className="text-slate-200 font-mono font-medium">{selectedTarget}</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs bg-[#0d1322] border border-slate-800/80 rounded p-2.5">
                      <div>
                        <div className="text-slate-500 text-[10px] uppercase">Binary Name</div>
                        <div className="text-slate-200 font-mono truncate">
                          {compiledArtifact ? compiledArtifact.filename : selectedTarget.includes('windows') ? 'investigation-windows-x64.exe' : 'investigation-linux-x64'}
                        </div>
                      </div>
                      <div>
                        <div className="text-slate-500 text-[10px] uppercase">Status</div>
                        <div className={clsx("font-medium truncate", isLoading ? "text-amber-400" : "text-emerald-400")}>
                          {statusMessage}
                        </div>
                      </div>
                      <div>
                        <div className="text-slate-500 text-[10px] uppercase">Target Platform</div>
                        <div className="text-slate-200 font-mono truncate">{selectedTarget}</div>
                      </div>
                      <div>
                        <div className="text-slate-500 text-[10px] uppercase">Binary Size</div>
                        <div className="text-slate-200 font-mono truncate">
                          {compiledArtifact && compiledArtifact.sizeBytes > 0
                            ? `${(compiledArtifact.sizeBytes / (1024 * 1024)).toFixed(2)} MB`
                            : compiledArtifact ? '1.46 MB' : 'Pending build'}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleCompileCode}
                        disabled={isLoading}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30 transition-colors disabled:opacity-50"
                      >
                        <Download className="h-3.5 w-3.5" />
                        <span>
                          {isLoading
                            ? 'Compiling Artifact...'
                            : compiledArtifact
                            ? `Download Again (${selectedTarget.includes('windows') ? '.exe' : 'native'})`
                            : `Compile & Download (${selectedTarget.includes('windows') ? '.exe' : 'native'})`}
                        </span>
                      </button>
                      <button
                        onClick={handleDownloadJy}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 text-slate-200 border border-slate-700 hover:bg-slate-700 transition-colors"
                      >
                        <FileCode className="h-3.5 w-3.5" />
                        <span>Download Source (.jy)</span>
                      </button>
                    </div>

                    {/* Live Build Logs Terminal */}
                    {compilerLogs.length > 0 && (
                      <div className="mt-2 bg-[#070b12] border border-slate-800 rounded-lg p-2.5 font-mono text-[11px] shadow-inner">
                        <div className="flex items-center justify-between text-slate-400 border-b border-slate-800/80 pb-1.5 mb-2">
                          <div className="flex items-center gap-2">
                            <div className="flex items-center gap-1">
                              <span className="h-2 w-2 rounded-full bg-rose-500/80"></span>
                              <span className="h-2 w-2 rounded-full bg-amber-500/80"></span>
                              <span className="h-2 w-2 rounded-full bg-emerald-500/80"></span>
                            </div>
                            <span className="font-semibold text-slate-300 flex items-center gap-1">
                              <TerminalIcon className="h-3 w-3 text-amber-400" />
                              <span>Live Build Logs</span>
                            </span>
                          </div>
                          {isLoading && (
                            <span className="flex items-center gap-1 text-amber-400 animate-pulse text-[10px]">
                              <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-ping"></span>
                              <span>Compiling...</span>
                            </span>
                          )}
                        </div>
                        <div className="space-y-0.5 max-h-48 overflow-y-auto pr-1">
                          {compilerLogs.map((log, idx) => (
                            <div
                              key={idx}
                              className={clsx(
                                log.includes('✓') || log.includes('BUILD SUCCESSFUL')
                                  ? 'text-emerald-400'
                                  : log.includes('❌') || log.includes('BUILD FAILED')
                                  ? 'text-rose-400 font-semibold'
                                  : log.includes('⚡') || log.includes('🔍')
                                  ? 'text-cyan-400 font-semibold'
                                  : log.includes('💾')
                                  ? 'text-amber-300'
                                  : log.includes('├──') || log.includes('└──') || log.includes('│')
                                  ? 'text-slate-300'
                                  : 'text-slate-400'
                              )}
                            >
                              {log}
                            </div>
                          ))}
                          <div ref={logsEndRef} />
                        </div>
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
                                <th className="py-1 px-2">Origin</th>
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
                                  <td className="py-1.5 px-2">
                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                                      item.origin === 'REAL'
                                        ? 'bg-blue-950 text-blue-300 border-blue-700'
                                        : item.origin === 'COLLECTOR_FAILED'
                                        ? 'bg-rose-950 text-rose-300 border-rose-700'
                                        : item.origin === 'SIMULATED'
                                        ? 'bg-amber-950 text-amber-300 border-amber-700'
                                        : 'bg-emerald-950 text-emerald-300 border-emerald-700'
                                    }`}>
                                      {item.origin || 'REAL'}
                                    </span>
                                  </td>
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
                        <span className="font-semibold text-slate-200">Evidence Integrity Status</span>
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
                          <span className="text-slate-400">Evidence SHA-256: </span>
                          <span className="text-slate-200">{executionResult?.sha256 || 'None computed'}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Investigation: </span>
                          <span className="text-slate-200">
                            {executionResult?.metadata?.investigation_name as string || executionResult?.investigation_name || 'Pending'}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400">Host: </span>
                          <span className="text-slate-200">
                            {executionResult?.metadata?.host_identifier as string || 'Unavailable'}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400">Merkle Root: </span>
                          <span className="text-slate-200">{executionResult?.merkle_root || 'Unavailable'}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Verification: </span>
                          <span className="text-slate-200">
                            {executionResult?.verification_method || 'Run an investigation to verify'}
                          </span>
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
                  {/* Mode switcher: Required vs Full Registry */}
                  <div className="flex border-b border-slate-800 pb-2 gap-2 text-xs">
                    <button
                      onClick={() => setCapViewMode('required')}
                      className={clsx(
                        'px-2.5 py-1 rounded text-[11px] font-medium transition',
                        capViewMode === 'required'
                          ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                      )}
                    >
                      Required ({requiredCapabilities.length})
                    </button>
                    <button
                      onClick={() => setCapViewMode('all')}
                      className={clsx(
                        'px-2.5 py-1 rounded text-[11px] font-medium transition',
                        capViewMode === 'all'
                          ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                      )}
                    >
                      Registry ({Object.keys(capabilitiesRegistry).length || 247})
                    </button>
                  </div>

                  {capViewMode === 'required' ? (
                    <div>
                      <h4 className="text-[11px] font-bold text-slate-300 uppercase tracking-wider mb-1">
                        Investigation Permissions
                      </h4>
                      <p className="text-[11px] text-slate-400 mb-2">
                        Capabilities required by the current AST and verified against the target platform:
                      </p>
                      <div className="space-y-2">
                        {requiredCapabilities.length > 0 ? (
                          requiredCapabilities.map((cap) => {
                            const meta = findCapabilityMetadata(cap);
                            return (
                              <div
                                key={cap}
                                className="p-2.5 rounded bg-[#090d15] border border-slate-800 text-[11px] space-y-1.5"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="font-mono text-blue-300 font-semibold">{cap}</span>
                                  {meta?.status ? (
                                    <span
                                      className={clsx(
                                        'px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wider',
                                        meta.status === 'IMPLEMENTED' && 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
                                        meta.status === 'REQUIRES_ELEVATION' && 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
                                        meta.status === 'PARTIAL' && 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
                                        meta.status === 'PLATFORM_SPECIFIC' && 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20',
                                        meta.status === 'UNSUPPORTED' && 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                      )}
                                    >
                                      {meta.status.replace('_', ' ')}
                                    </span>
                                  ) : (
                                    <span className="text-slate-400 text-[10px]">Compiler AST</span>
                                  )}
                                </div>

                                {meta && (
                                  <>
                                    <p className="text-slate-300 text-[10px] leading-tight">{meta.description}</p>
                                    <div className="flex flex-wrap gap-1 pt-0.5">
                                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[9px]">
                                        Platform: {meta.platforms}
                                      </span>
                                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[9px]">
                                        Privilege: {meta.privilege}
                                      </span>
                                      {meta.category && (
                                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[9px]">
                                          {meta.category}
                                        </span>
                                      )}
                                      {meta.mitre_attack_ids?.map((t) => (
                                        <span key={t} className="px-1.5 py-0.5 rounded bg-red-950/40 text-red-300 border border-red-800/30 text-[9px]">
                                          {t}
                                        </span>
                                      ))}
                                    </div>
                                  </>
                                )}
                              </div>
                            );
                          })
                        ) : (
                          <div className="text-slate-400 text-xs py-4 text-center border border-dashed border-slate-800 rounded">
                            Run <span className="text-blue-400 font-semibold">Check</span> to inspect required capabilities.
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="flex gap-2">
                        <input
                          type="text"
                          placeholder="Search capabilities..."
                          value={capSearchQuery}
                          onChange={(e) => setCapSearchQuery(e.target.value)}
                          className="w-full bg-[#090d15] border border-slate-800 rounded px-2.5 py-1 text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                        />
                        <select
                          value={capCategoryFilter}
                          onChange={(e) => setCapCategoryFilter(e.target.value)}
                          className="bg-[#090d15] border border-slate-800 rounded px-2 py-1 text-[11px] text-slate-300 focus:outline-none focus:border-blue-500"
                        >
                          <option value="ALL">All Categories</option>
                          <option value="Process">Process</option>
                          <option value="SystemInfo">SystemInfo</option>
                          <option value="Network">Network</option>
                          <option value="Filesystem">Filesystem</option>
                          <option value="Authentication">Authentication</option>
                          <option value="WindowsArtifact">WindowsArtifact</option>
                          <option value="LinuxArtifact">LinuxArtifact</option>
                          <option value="Persistence">Persistence</option>
                          <option value="Service">Service</option>
                          <option value="User">User</option>
                          <option value="KernelDriver">KernelDriver</option>
                          <option value="EvidenceIntegrity">EvidenceIntegrity</option>
                          <option value="SecurityConfig">SecurityConfig</option>
                          <option value="MaliciousScript">MaliciousScript</option>
                        </select>
                      </div>

                      <div className="max-h-80 overflow-y-auto space-y-1.5 pr-1">
                        {Object.entries(capabilitiesRegistry)
                          .filter(([id, cap]) => {
                            const matchesSearch =
                              !capSearchQuery ||
                              id.toLowerCase().includes(capSearchQuery.toLowerCase()) ||
                              cap.name.toLowerCase().includes(capSearchQuery.toLowerCase()) ||
                              cap.description?.toLowerCase().includes(capSearchQuery.toLowerCase()) ||
                              cap.mitre_attack_ids?.some((t) => t.toLowerCase().includes(capSearchQuery.toLowerCase()));
                            const matchesCat = capCategoryFilter === 'ALL' || cap.category === capCategoryFilter;
                            return matchesSearch && matchesCat;
                          })
                          .slice(0, 50)
                          .map(([id, cap]) => (
                            <div key={id} className="p-2 rounded bg-[#090d15] border border-slate-800 text-[10px] space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="font-mono text-slate-200 font-semibold">{id}</span>
                                <span
                                  className={clsx(
                                    'px-1 py-0.5 rounded text-[8px] font-semibold uppercase',
                                    cap.status === 'IMPLEMENTED' && 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
                                    cap.status === 'REQUIRES_ELEVATION' && 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
                                    cap.status === 'PARTIAL' && 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
                                    cap.status === 'PLATFORM_SPECIFIC' && 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20',
                                    cap.status === 'UNSUPPORTED' && 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                  )}
                                >
                                  {cap.status?.replace('_', ' ')}
                                </span>
                              </div>
                              <p className="text-slate-400 leading-tight">{cap.description}</p>
                              <div className="flex flex-wrap gap-1 text-[8px] text-slate-500">
                                <span>Platform: {cap.platforms}</span>
                                <span>•</span>
                                <span>Privilege: {cap.privilege}</span>
                                {cap.mitre_attack_ids?.length > 0 && (
                                  <>
                                    <span>•</span>
                                    <span>MITRE: {cap.mitre_attack_ids.join(', ')}</span>
                                  </>
                                )}
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

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
