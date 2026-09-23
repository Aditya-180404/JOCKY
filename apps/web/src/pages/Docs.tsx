import { useState } from 'react';
import { SiteHeader } from '../components/SiteHeader';
import { SiteFooter } from '../components/SiteFooter';
import {
  Terminal,
  ShieldCheck,
  Cpu,
  Lock,
} from 'lucide-react';

export function DocsPage() {
  const [activeSection, setActiveSection] = useState('cli');

  const cliCommands = [
    {
      cmd: 'traceforge check <file.tfg>',
      desc: 'Validates source syntax, AST, and semantic capability constraints.',
    },
    {
      cmd: 'traceforge compile <file.tfg> --target windows --arch x64',
      desc: 'Compiles the .tfg investigation into a standalone native executable artifact.',
    },
    {
      cmd: 'traceforge build <file.tfg>',
      desc: 'Alias for speed-optimized compilation into release binary.',
    },
    {
      cmd: 'traceforge run <file.tfg>',
      desc: 'Compiles and immediately executes the investigation on the current host.',
    },
    {
      cmd: 'traceforge fmt <file.tfg> [--write]',
      desc: 'Parses and formats source code into normalized TraceForge syntax.',
    },
    {
      cmd: 'traceforge inspect <file.tfg> --format [tokens|ast|ir]',
      desc: 'Dumps lexer tokens, AST hierarchy, or Intermediate Representation (IR).',
    },
    {
      cmd: 'traceforge verify <artifact/evidence.json>',
      desc: 'Verifies SHA-256 cryptographic checksums against sidecar metadata to detect tampering.',
    },
    {
      cmd: 'traceforge target list',
      desc: 'Lists all supported compilation target platforms and architectures.',
    },
  ];

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 flex flex-col font-sans">
      <SiteHeader />

      <main className="flex-1 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-10 w-full flex flex-col md:flex-row gap-8">
        {/* Navigation Sidebar */}
        <aside className="w-full md:w-60 shrink-0 space-y-1">
          <h3 className="px-3 text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2 font-mono">
            Documentation
          </h3>
          {[
            { id: 'cli', label: 'CLI Toolchain Reference', icon: Terminal },
            { id: 'architecture', label: 'Compiler Architecture', icon: Cpu },
            { id: 'evidence', label: 'Evidence & Integrity Spec', icon: ShieldCheck },
            { id: 'security', label: 'Security & Safety Model', icon: Lock },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveSection(item.id)}
              className={`w-full text-left px-3 py-2 rounded text-xs font-medium flex items-center gap-2 transition-colors ${
                activeSection === item.id
                  ? 'bg-blue-600/10 text-blue-400 font-semibold border border-blue-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <item.icon className="h-4 w-4" />
              <span>{item.label}</span>
            </button>
          ))}
        </aside>

        {/* Content Area */}
        <div className="flex-1 space-y-8 bg-[#0e1422] border border-slate-800 rounded p-6 sm:p-8">
          {activeSection === 'cli' && (
            <div className="space-y-6">
              <div>
                <h1 className="text-xl font-bold font-mono text-white">CLI Toolchain Reference</h1>
                <p className="mt-1 text-xs text-slate-400">
                  Command-line interface for checking, compiling, running, and verifying TRACEFORGE investigations.
                </p>
              </div>

              <div className="space-y-3">
                {cliCommands.map((c) => (
                  <div key={c.cmd} className="bg-[#090d15] p-3.5 rounded border border-slate-800 space-y-1">
                    <div className="font-mono text-xs text-blue-300 font-semibold">{c.cmd}</div>
                    <div className="text-xs text-slate-400">{c.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeSection === 'architecture' && (
            <div className="space-y-5 text-xs text-slate-300 leading-relaxed">
              <div>
                <h1 className="text-xl font-bold font-mono text-white mb-1">Compiler Architecture</h1>
                <p className="text-slate-400">
                  Deterministic pipeline transforming domain-specific `.tfg` source into native forensic binaries.
                </p>
              </div>

              <div className="p-4 rounded bg-[#090d15] border border-slate-800 font-mono text-[11px] space-y-2">
                <div>[Source .tfg] → Lexer (Token Scanner with Span Tracking)</div>
                <div>    ↓</div>
                <div>Parser → AST (Abstract Syntax Tree Construction)</div>
                <div>    ↓</div>
                <div>Semantic Analyzer → Type checking & Capability Inference</div>
                <div>    ↓</div>
                <div>IR Generator → Canonical Intermediate Representation</div>
                <div>    ↓</div>
                <div>Backend Engine → Target Native Code Generation (windows-x64 / linux-x64)</div>
                <div>    ↓</div>
                <div>[Standalone Executable Binary + SHA-256 Metadata Sidecar]</div>
              </div>

              <h2 className="text-sm font-bold text-white font-mono mt-4">Capability Model</h2>
              <p>
                The compiler examines the operations specified in the `collect` blocks and computes the minimal set
                of operating system capabilities needed for the binary to execute. Unused permissions are omitted.
              </p>
            </div>
          )}

          {activeSection === 'evidence' && (
            <div className="space-y-5 text-xs text-slate-300 leading-relaxed">
              <div>
                <h1 className="text-xl font-bold font-mono text-white mb-1">Evidence & Integrity Specification</h1>
                <p className="text-slate-400">
                  Cryptographic guarantees preserving chain of custody and non-repudiation.
                </p>
              </div>

              <div className="p-4 rounded bg-[#090d15] border border-slate-800 space-y-3 font-mono text-[11px]">
                <div className="font-bold text-slate-200">1. Evidence Envelope</div>
                <p className="text-slate-400 font-sans">
                  The evidence output file is a canonical JSON document containing all requested telemetry
                  (system information, process trees, network sockets, file metadata).
                </p>

                <div className="font-bold text-slate-200 pt-2">2. Metadata Sidecar (`.meta.json`)</div>
                <p className="text-slate-400 font-sans">
                  Generated simultaneously with the evidence. Contains the SHA-256 hash of the evidence file,
                  source hash, compiler hash, hostname, UTC collection timestamp, and investigation identifier.
                </p>

                <div className="font-bold text-slate-200 pt-2">3. Verification Command</div>
                <div className="text-blue-300">traceforge verify evidence.json</div>
                <p className="text-slate-400 font-sans">
                  Recalculates the evidence hash and matches against sidecar. Exit code 0 if valid; exit code 1 if tampered.
                </p>
              </div>
            </div>
          )}

          {activeSection === 'security' && (
            <div className="space-y-5 text-xs text-slate-300 leading-relaxed">
              <div>
                <h1 className="text-xl font-bold font-mono text-white mb-1">Security & Safety Model</h1>
                <p className="text-slate-400">
                  Strict boundaries ensuring non-destructive forensic operations.
                </p>
              </div>

              <div className="grid grid-cols-1 gap-3">
                <div className="p-3.5 rounded bg-[#090d15] border border-slate-800">
                  <h3 className="font-bold text-white mb-1">Read-Only Operation</h3>
                  <p className="text-slate-400">
                    TraceForge collection primitives only query existing state. Handles are opened with read-only
                    rights (`PROCESS_QUERY_LIMITED_INFORMATION`, read-only file streams).
                  </p>
                </div>

                <div className="p-3.5 rounded bg-[#090d15] border border-slate-800">
                  <h3 className="font-bold text-white mb-1">No Kernel Modification</h3>
                  <p className="text-slate-400">
                    No custom kernel drivers are loaded; no hooks or system call tables are altered.
                  </p>
                </div>

                <div className="p-3.5 rounded bg-[#090d15] border border-slate-800">
                  <h3 className="font-bold text-white mb-1">Zero Persistence Footprint</h3>
                  <p className="text-slate-400">
                    Generated binaries execute as single-shot tasks and terminate immediately after evidence export.
                    No services, registry keys, or scheduled tasks are left behind.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
