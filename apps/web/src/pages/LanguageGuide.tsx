import { useState } from 'react';
import { SiteHeader } from '../components/SiteHeader';
import { SiteFooter } from '../components/SiteFooter';
import { Link } from 'react-router-dom';
import {
  Play,
  Copy,
  Check,
  ChevronRight,
  Search,
} from 'lucide-react';
import clsx from 'clsx';

interface GuideSection {
  id: string;
  title: string;
  category: string;
  content: string;
  codeSnippet?: string;
}

const GUIDE_SECTIONS: GuideSection[] = [
  {
    id: 'what_is_jockey',
    title: 'What is jockey?',
    category: 'Getting Started',
    content: `jockey is a domain-specific forensic programming language designed to author, compile, and execute digital incident response investigations deterministically.
Unlike ad-hoc shell scripts, jockey programs compile into secure, tamper-evident forensic binaries that emit structured evidence bundles verified by SHA-256 cryptographic digests.`,
  },
  {
    id: 'installation',
    title: 'Installation',
    category: 'Getting Started',
    content: `You can use jockey directly in your browser via the Web IDE, or install the native standalone CLI toolchain and Desktop IDE for Windows or Linux.
No Rust compiler or development tools are required on target endpoint machines.`,
    codeSnippet: `# Verify and run CLI
jockey --version
jockey check investigation.tfg`,
  },
  {
    id: 'first_program',
    title: 'First Program',
    category: 'Language Basics',
    content: `Every jockey file contains an \`investigation\` block defining one or more collectors and an export target.`,
    codeSnippet: `investigation "first_triage" {
    collect system_info
    collect processes
    export evidence "evidence.json"
}`,
  },
  {
    id: 'syntax_rules',
    title: 'Syntax & Grammar',
    category: 'Language Basics',
    content: `jockey syntax uses clean curly-brace blocks without requiring trailing semicolons.
Keywords include: \`investigation\`, \`metadata\`, \`collect\`, \`export\`, \`evidence\`, \`where\`, \`limit\`, \`hash\`, \`recursive\`.`,
  },
  {
    id: 'investigations',
    title: 'Investigations Block',
    category: 'Language Basics',
    content: `An investigation block encapsulates an isolated triage scope. It names the session and defines execution boundaries.`,
    codeSnippet: `investigation "incident_response_alpha" {
    // Collectors and options go here
    collect system_info
    export evidence "incident.json"
}`,
  },
  {
    id: 'metadata',
    title: 'Metadata Block',
    category: 'Language Basics',
    content: `You can attach case numbers, analyst names, priority levels, and category tags inside a \`metadata\` block using either \`:\` or \`=\`.`,
    codeSnippet: `investigation "triage_case_104" {
    metadata {
        case_id = "IR-2026-0923"
        analyst = "Forensic Lead"
        priority = "Critical"
    }

    collect system_info
    export evidence "case_104.json"
}`,
  },
  {
    id: 'system_info',
    title: 'System Information Collector',
    category: 'Collectors',
    content: `The \`collect system_info\` collector extracts hardware architecture, operating system release, host identifiers, CPU count, and memory statistics.`,
    codeSnippet: `collect system_info`,
  },
  {
    id: 'processes',
    title: 'Process Collector',
    category: 'Collectors',
    content: `The \`collect processes\` collector extracts process tree data with options for PID, PPID, name, command line, user, start time, and on-demand executable SHA-256 hashing.`,
    codeSnippet: `collect processes {
    pid
    name
    parent
    command_line
    user
    hash.sha256
}`,
  },
  {
    id: 'network',
    title: 'Network Connections Collector',
    category: 'Collectors',
    content: `The \`collect network_connections\` collector inspects socket tables to capture listening and established TCP/UDP endpoints with associated PIDs.`,
    codeSnippet: `collect network_connections`,
  },
  {
    id: 'users',
    title: 'User Activity Collector',
    category: 'Collectors',
    content: `Filter processes or system events by user account identifier using the \`where\` expression.`,
    codeSnippet: `collect processes {
    pid
    name
    user
} where user == "root"`,
  },
  {
    id: 'filesystem',
    title: 'Filesystem Collector',
    category: 'Collectors',
    content: `The \`collect files "<path>"\` collector recursively scans target directories and hashes file contents.`,
    codeSnippet: `collect files "/etc" {
    recursive
    hash.sha256
} limit 50`,
  },
  {
    id: 'services_logs',
    title: 'Services & Logs',
    category: 'Collectors',
    content: `Inspect system log streams and background services safely using the \`collect logs\` statement.`,
    codeSnippet: `collect logs {
    source: "system"
}`,
  },
  {
    id: 'filtering_limit',
    title: 'Filtering & Limits',
    category: 'Query Capabilities',
    content: `Limit output size with \`limit <N>\` to prevent unbounded memory growth during high-volume triage. Filter records with boolean expressions in \`where\` clauses.`,
    codeSnippet: `collect processes {
    pid
    name
} limit 25`,
  },
  {
    id: 'evidence_model',
    title: 'Evidence & SHA-256',
    category: 'Integrity & Verification',
    content: `jockey evidence is serialized to structured JSON accompanied by a \`.meta.json\` cryptographic sidecar.
The SHA-256 digest is calculated over the canonical byte stream.`,
  },
  {
    id: 'verification',
    title: 'Integrity Verification',
    category: 'Integrity & Verification',
    content: `Verify evidence bundles anytime using \`jockey verify <evidence.json>\`. Any modification to the data or metadata triggers a tamper alert.`,
    codeSnippet: `jockey verify processes.json
# Output:
# Integrity: VALID
# SHA-256: 5244f44aae2f7445e8d0f868276323132a50e3ecf9169fa60578962851f6405b`,
  },
  {
    id: 'security_model',
    title: 'Security Model & Safety Boundaries',
    category: 'Security',
    content: `jockey strictly isolates forensic operations:
- Defensive and read-only collection operations only
- No arbitrary shell, PowerShell, or Python execution
- No persistence, evasion, AV/EDR bypass mechanisms
- No kernel modification or driver loading
- Compiled binaries are single-shot with zero persistence footprint`,
  },
];

export function LanguageGuide() {
  const [selectedId, setSelectedId] = useState(GUIDE_SECTIONS[0].id);
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState<string | null>(null);

  const selectedSection = GUIDE_SECTIONS.find((s) => s.id === selectedId) || GUIDE_SECTIONS[0];

  const filteredSections = GUIDE_SECTIONS.filter(
    (s) =>
      s.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.content.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.category.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const categories = Array.from(new Set(GUIDE_SECTIONS.map((s) => s.category)));

  const handleCopyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(code);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 flex flex-col font-sans">
      <SiteHeader />

      <main className="flex-1 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full flex flex-col md:flex-row gap-8">
        {/* Left Table of Contents */}
        <aside className="w-full md:w-64 shrink-0 space-y-4">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search guide..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded bg-[#0e1422] border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>

          <div className="bg-[#0e1422] border border-slate-800 rounded p-3 space-y-4 max-h-[calc(100vh-220px)] overflow-y-auto">
            {categories.map((cat) => {
              const catSections = filteredSections.filter((s) => s.category === cat);
              if (catSections.length === 0) return null;
              return (
                <div key={cat} className="space-y-1">
                  <h4 className="px-2 text-[10px] font-semibold text-slate-500 uppercase tracking-wider font-mono">
                    {cat}
                  </h4>
                  {catSections.map((sec) => (
                    <button
                      key={sec.id}
                      onClick={() => setSelectedId(sec.id)}
                      className={clsx(
                        'w-full text-left px-2 py-1 rounded text-xs transition-colors flex items-center justify-between',
                        selectedId === sec.id
                          ? 'bg-blue-600/15 text-blue-400 font-semibold border border-blue-500/30'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                      )}
                    >
                      <span>{sec.title}</span>
                      {selectedId === sec.id && <ChevronRight className="h-3 w-3" />}
                    </button>
                  ))}
                </div>
              );
            })}
          </div>
        </aside>

        {/* Right Content Panel */}
        <article className="flex-1 bg-[#0e1422] border border-slate-800 rounded p-6 sm:p-8 space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <span className="text-[11px] font-mono text-blue-400 uppercase tracking-wider">
              {selectedSection.category}
            </span>
            <h1 className="text-2xl font-bold font-mono text-white mt-1">
              {selectedSection.title}
            </h1>
          </div>

          <div className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap font-sans">
            {selectedSection.content}
          </div>

          {selectedSection.codeSnippet && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                <span>Code Example:</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopyCode(selectedSection.codeSnippet!)}
                    className="flex items-center gap-1 text-slate-400 hover:text-slate-200"
                  >
                    {copied === selectedSection.codeSnippet ? (
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                    <span>Copy</span>
                  </button>
                  <Link
                    to="/ide"
                    className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-blue-600/20 text-blue-300 border border-blue-500/30 hover:bg-blue-600/30"
                  >
                    <Play className="h-3 w-3" />
                    Open in Web IDE
                  </Link>
                </div>
              </div>
              <div className="p-3.5 rounded bg-[#090d15] font-mono text-xs text-slate-200 border border-slate-800 overflow-x-auto">
                <pre>{selectedSection.codeSnippet}</pre>
              </div>
            </div>
          )}
        </article>
      </main>

      <SiteFooter />
    </div>
  );
}
