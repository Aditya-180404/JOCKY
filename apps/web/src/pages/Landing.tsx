import { Link } from 'react-router-dom';
import { SiteHeader } from '../components/SiteHeader';
import { SiteFooter } from '../components/SiteFooter';
import {
  Play,
  Download,
  BookOpen,
  Code2,
  ShieldCheck,
  Cpu,
  Layers,
  Lock,
  ArrowRight,
} from 'lucide-react';

export function Landing() {
  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 flex flex-col">
      <SiteHeader />

      {/* Hero Section */}
      <section className="border-b border-slate-800 bg-[#0e1422] py-16">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded border border-blue-500/30 bg-blue-500/10 text-blue-300 text-xs font-mono mb-6">
            <ShieldCheck className="h-3.5 w-3.5 text-blue-400" />
            <span>Digital Forensic Programming Language & Toolchain</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-bold tracking-tight text-white font-mono leading-tight">
            TRACEFORGE
          </h1>

          <p className="mt-3 text-xl sm:text-2xl font-semibold text-slate-200">
            Forensic Programming. Built for Investigation.
          </p>

          <p className="mt-4 text-base text-slate-400 max-w-2xl mx-auto leading-relaxed">
            TRACEFORGE is a domain-specific forensic programming language and platform for building,
            executing, and managing computer and network investigations.
          </p>

          {/* Primary Action Buttons */}
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              to="/ide"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded bg-blue-600 hover:bg-blue-700 text-white font-medium text-sm transition-colors"
            >
              <Play className="h-4 w-4 fill-current" />
              Open Web IDE
            </Link>

            <Link
              to="/download"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-sm transition-colors"
            >
              <Download className="h-4 w-4" />
              Download Compiler
            </Link>

            <Link
              to="/docs"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded text-slate-300 hover:text-white hover:bg-slate-800/60 font-medium text-sm transition-colors"
            >
              <BookOpen className="h-4 w-4" />
              Read Documentation
            </Link>

            <Link
              to="/examples"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded text-slate-300 hover:text-white hover:bg-slate-800/60 font-medium text-sm transition-colors"
            >
              <Code2 className="h-4 w-4" />
              View Examples
            </Link>
          </div>
        </div>
      </section>

      {/* Code Preview & Dual Model Section */}
      <section className="py-12 border-b border-slate-800 bg-[#090d15]">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
            {/* Left: Code Box */}
            <div className="rounded border border-slate-800 bg-[#0c111c] overflow-hidden">
              <div className="h-9 bg-[#111827] border-b border-slate-800 px-4 flex items-center justify-between">
                <span className="font-mono text-xs text-slate-300">process_triage.tfg</span>
                <span className="font-mono text-[11px] text-emerald-400">Validated</span>
              </div>
              <pre className="p-4 font-mono text-xs leading-relaxed text-slate-300 overflow-x-auto">
{`investigation "process_triage" {
    metadata {
      case_id = "INC-2026-09"
      priority = "High"
    }

    collect system_info

    collect processes {
        pid
        name
        parent
        command_line
        user
        hash.sha256
    } where cpu_percent > 20 limit 50

    export evidence "process_triage.json"
}`}
              </pre>
            </div>

            {/* Right: Local vs Cloud Model */}
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold text-white mb-2">Two Complementary Execution Models</h2>
                <p className="text-sm text-slate-400 leading-relaxed">
                  TraceForge is architected to operate both as an offline, zero-dependency local forensic compiler
                  and as an integrated web investigation workspace.
                </p>
              </div>

              <div className="space-y-4">
                <div className="p-3.5 rounded border border-slate-800 bg-[#111827]">
                  <div className="flex items-center gap-2 font-mono text-xs font-semibold text-blue-400 mb-1">
                    <span>1. LOCAL STANDALONE COMPILER</span>
                  </div>
                  <p className="text-xs text-slate-300 font-mono">
                    Write .tfg → traceforge compile → Standalone .exe → Execute on target host → SHA-256 sidecar
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    Zero external runtime dependencies. Runs offline on air-gapped systems.
                  </p>
                </div>

                <div className="p-3.5 rounded border border-slate-800 bg-[#111827]">
                  <div className="flex items-center gap-2 font-mono text-xs font-semibold text-emerald-400 mb-1">
                    <span>2. WEB WORKSPACE & INVESTIGATION PLATFORM</span>
                  </div>
                  <p className="text-xs text-slate-300 font-mono">
                    Web IDE → AST/IR Diagnostics → Sandbox Execution → Verifiable Evidence Envelope
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    Browser-based authoring with syntax highlighting, compiler diagnostics, and integrity verification.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Product Pillars */}
      <section className="py-14 border-b border-slate-800 bg-[#0b0f17]">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="mb-10 text-center">
            <h2 className="text-2xl font-bold text-white font-mono">Core Forensic Subsystems</h2>
            <p className="text-sm text-slate-400 mt-1">
              Purpose-built capabilities engineered specifically for digital incident response.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* 1. Language */}
            <div className="p-5 rounded border border-slate-800 bg-[#111827]">
              <Code2 className="h-5 w-5 text-blue-400 mb-3" />
              <h3 className="text-sm font-bold text-white mb-1.5 font-mono">Forensic Language (.tfg)</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Declarative syntax designed for digital evidence collection. Define metadata, target forensic
                artifacts, apply field projections, and specify strict export paths without procedural boilerplate.
              </p>
            </div>

            {/* 2. Toolchain */}
            <div className="p-5 rounded border border-slate-800 bg-[#111827]">
              <Cpu className="h-5 w-5 text-blue-400 mb-3" />
              <h3 className="text-sm font-bold text-white mb-1.5 font-mono">Cross-Platform Toolchain</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  The compiler models Windows x64 and Linux x86_64 targets. Linux collection is implemented; Windows
                  runtime collectors and native artifact delivery remain in development.
              </p>
            </div>

            {/* 3. Web IDE */}
            <div className="p-5 rounded border border-slate-800 bg-[#111827]">
              <Play className="h-5 w-5 text-blue-400 mb-3" />
              <h3 className="text-sm font-bold text-white mb-1.5 font-mono">Web IDE</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Integrated browser developer environment with Monaco editor, syntax highlighting, live compiler
                diagnostics, and real sandboxed execution.
              </p>
            </div>

            {/* 4. Evidence Integrity */}
            <div className="p-5 rounded border border-slate-800 bg-[#111827]">
              <ShieldCheck className="h-5 w-5 text-emerald-400 mb-3" />
              <h3 className="text-sm font-bold text-white mb-1.5 font-mono">Evidence Integrity</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Deterministic SHA-256 sidecars (.meta.json), cryptographic hashes, and Merkle tree verification.
                Any byte alteration of exported evidence is detected immediately.
              </p>
            </div>

            {/* 5. Investigation Platform */}
            <div className="p-5 rounded border border-slate-800 bg-[#111827]">
              <Layers className="h-5 w-5 text-blue-400 mb-3" />
              <h3 className="text-sm font-bold text-white mb-1.5 font-mono">Investigation Platform</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Organize tools, investigation runs, host targets, evidence files, findings, and forensic reports
                with complete audit logging.
              </p>
            </div>

            {/* 6. Local-First Design */}
            <div className="p-5 rounded border border-slate-800 bg-[#111827]">
              <Lock className="h-5 w-5 text-blue-400 mb-3" />
              <h3 className="text-sm font-bold text-white mb-1.5 font-mono">Local-First Safety</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Read-only safety guarantees: no kernel hooking, no process injection, no persistence creation,
                no credential access. Fully functional in offline, classified environments.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Platform Roadmap / Future Scope */}
      <section className="py-14 border-b border-slate-800 bg-[#090d15]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="mb-8">
            <h2 className="text-xl font-bold text-white font-mono">Architecture Status & Roadmap</h2>
            <p className="text-xs text-slate-400 mt-1">
              Transparent disclosure of current production components versus roadmap expansion.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {/* Available */}
            <div className="p-4 rounded border border-slate-800 bg-[#0e1422]">
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold text-white">Current Core Subsystems</span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  AVAILABLE
                </span>
              </div>
              <ul className="space-y-1.5 text-slate-400">
                <li>✓ TraceForge DSL Parser, AST, Semantic Analyzer & IR</li>
                <li>✓ Linux standalone executable code generation and runtime collectors</li>
                <li>• Windows target and native collectors are currently stubs</li>
                <li>✓ CLI Toolchain (`check`, `compile`, `run`, `verify`, `fmt`, `hash`)</li>
                <li>✓ SHA-256 Sidecar Generation & Tamper Detection</li>
                <li>✓ Web IDE with Monaco Editor & Real Compiler Integration</li>
              </ul>
            </div>

            {/* In Development */}
            <div className="p-4 rounded border border-slate-800 bg-[#0e1422]">
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold text-white">Platform Expansion</span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                  IN DEVELOPMENT
                </span>
              </div>
              <ul className="space-y-1.5 text-slate-400">
                <li>• Forensic Tool Repository Publishing & Versioning</li>
                <li>• Multi-Tenancy Organization Workspaces & RBAC</li>
                <li>• Asynchronous Worker Queue for Distributed Compilation</li>
                <li>• S3/MinIO Object Storage for Long-Term Evidence Retention</li>
                <li>• Automated CI/CD Cross-Compilation Pipeline</li>
              </ul>
            </div>

            {/* Planned */}
            <div className="p-4 rounded border border-slate-800 bg-[#0e1422]">
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold text-white">Enterprise & Multi-Host</span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  PLANNED
                </span>
              </div>
              <ul className="space-y-1.5 text-slate-400">
                <li>• Centralized Multi-Host Fleet Dispatch & Heartbeats</li>
                <li>• Signed Cryptographic Tool Packages & Verifiable Attestations</li>
                <li>• Enterprise Gateway Architecture with Mutual TLS</li>
                <li>• Automated Forensic Timeline Reconstruction</li>
              </ul>
            </div>

            {/* Research */}
            <div className="p-4 rounded border border-slate-800 bg-[#0e1422]">
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold text-white">Research & Advanced Integrity</span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  RESEARCH
                </span>
              </div>
              <ul className="space-y-1.5 text-slate-400">
                <li>• Immutable Public Blockchain Anchoring (Ethereum/Polygon)</li>
                <li>• Zero-Knowledge Proofs for Redacted Evidence Verification</li>
                <li>• LLVM/Inkwell Direct JIT Forensic Compilation</li>
                <li>• Advanced Memory Forensics & Anomaly Heuristics</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Footer Section */}
      <section className="py-12 bg-[#0c101a] text-center">
        <div className="max-w-3xl mx-auto px-4">
          <h2 className="text-xl font-bold text-white font-mono mb-2">
            Start Authoring Forensic Investigations
          </h2>
          <p className="text-xs text-slate-400 mb-6">
            Test canonical scripts directly in the Web IDE or download the standalone compiler for offline triage.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Link
              to="/ide"
              className="inline-flex items-center gap-2 px-4 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs transition-colors"
            >
              Open Web IDE <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            <Link
              to="/download"
              className="inline-flex items-center gap-2 px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs transition-colors"
            >
              Download Compiler v0.1.0
            </Link>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}