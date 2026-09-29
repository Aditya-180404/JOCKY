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
  Lock,
  ArrowRight,
  FileText,
} from 'lucide-react';

export function Landing() {
  return (
    <div className="t-page">
      <SiteHeader />

      {/* Hero Section */}
      <section className="border-b py-16" style={{ backgroundColor: 'var(--page-bg-dark)', borderColor: 'var(--border)' }}>
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <div
            className="inline-flex items-center gap-2 px-3 py-1 rounded border text-xs font-mono mb-6"
            style={{ borderColor: 'rgba(59,130,246,0.3)', backgroundColor: 'rgba(59,130,246,0.08)', color: '#60a5fa' }}
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Digital Forensic Programming Language &amp; Toolchain</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-bold tracking-tight font-mono leading-tight" style={{ color: 'var(--text)' }}>
            jocky
          </h1>

          <p className="mt-3 text-xl sm:text-2xl font-semibold" style={{ color: 'var(--text)' }}>
            Forensic Programming. Built for Investigation.
          </p>

          <p className="mt-4 text-base max-w-2xl mx-auto leading-relaxed" style={{ color: 'var(--text-muted)' }}>
            jocky is a domain-specific forensic programming language and standalone compiler for building,
            executing, and verifying computer and network investigations.
          </p>

          {/* Primary Action Buttons */}
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              to="/ide"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded bg-blue-600 hover:bg-blue-700 text-white font-medium text-sm transition-colors shadow-sm"
            >
              <Play className="h-4 w-4 fill-current" />
              Open Web IDE
            </Link>

            <Link
              to="/download"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded font-medium text-sm transition-colors border"
              style={{ backgroundColor: 'var(--surface)', color: 'var(--text)', borderColor: 'var(--border)' }}
            >
              <Download className="h-4 w-4" />
              Download Compiler
            </Link>

            <Link
              to="/docs"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded font-medium text-sm transition-colors hover:bg-slate-100 dark:hover:bg-slate-800/60"
              style={{ color: 'var(--text-muted)' }}
            >
              <BookOpen className="h-4 w-4" />
              Read Documentation
            </Link>

            <Link
              to="/examples"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded font-medium text-sm transition-colors hover:bg-slate-100 dark:hover:bg-slate-800/60"
              style={{ color: 'var(--text-muted)' }}
            >
              <Code2 className="h-4 w-4" />
              View Examples
            </Link>
          </div>
        </div>
      </section>

      {/* Code Preview & Dual Model Section */}
      <section className="py-12 border-b" style={{ backgroundColor: 'var(--page-bg-alt)', borderColor: 'var(--border)' }}>
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
            {/* Left: Code Box — always dark */}
            <div className="rounded border overflow-hidden" style={{ backgroundColor: '#0c111c', borderColor: '#1e293b' }}>
              <div className="h-9 border-b px-4 flex items-center justify-between" style={{ backgroundColor: '#111827', borderColor: '#1e293b' }}>
                <span className="font-mono text-xs text-slate-300">process_triage.jy</span>
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

            {/* Right: Execution Model */}
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold mb-2" style={{ color: 'var(--text)' }}>Local-First Execution Model</h2>
                <p className="text-sm leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                  jocky is an offline-first forensic compiler. Write .jy source, compile to a standalone native binary,
                  execute on the target host, and verify evidence integrity with SHA-256.
                </p>
              </div>

              <div className="space-y-4">
                <div className="p-3.5 rounded border" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                  <div className="flex items-center gap-2 font-mono text-xs font-semibold text-blue-500 dark:text-blue-400 mb-1">
                    <span>LOCAL STANDALONE COMPILER</span>
                  </div>
                  <p className="text-xs font-mono" style={{ color: 'var(--text)' }}>
                    Write .jy → jocky compile → Standalone executable → Execute on target host → SHA-256 sidecar
                  </p>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                    Zero external runtime dependencies. Runs offline on air-gapped systems.
                  </p>
                </div>

                <div className="p-3.5 rounded border" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                  <div className="flex items-center gap-2 font-mono text-xs font-semibold text-emerald-600 dark:text-emerald-400 mb-1">
                    <span>WEB IDE FOR AUTHORING &amp; VALIDATION</span>
                  </div>
                  <p className="text-xs font-mono" style={{ color: 'var(--text)' }}>
                    Browser-based authoring with Monaco editor, live compiler diagnostics, and artifact download
                  </p>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                    Compile in the browser, download the native binary, run locally. No sandbox execution.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Product Pillars */}
      <section className="py-14 border-b" style={{ backgroundColor: 'var(--page-bg)', borderColor: 'var(--border)' }}>
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="mb-10 text-center">
            <h2 className="text-2xl font-bold font-mono" style={{ color: 'var(--text)' }}>Core Forensic Subsystems</h2>
            <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
              Purpose-built capabilities engineered specifically for digital incident response.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[
              { icon: <Code2 className="h-5 w-5 text-blue-500 dark:text-blue-400 mb-3" />, title: 'Forensic Language (.jy)', desc: 'Declarative syntax designed for digital evidence collection. Define metadata, target forensic artifacts, apply field projections, and specify strict export paths without procedural boilerplate.' },
              { icon: <Cpu className="h-5 w-5 text-blue-500 dark:text-blue-400 mb-3" />, title: 'Cross-Platform Toolchain', desc: 'The compiler models Windows x64 and Linux x86_64 targets. Linux collection is implemented; Windows runtime collectors and native artifact delivery remain in development.' },
              { icon: <Play className="h-5 w-5 text-blue-500 dark:text-blue-400 mb-3" />, title: 'Web IDE', desc: 'Browser-based authoring with Monaco editor, live compiler diagnostics, and native artifact download. Write, validate, and compile investigations directly in the browser.' },
              { icon: <ShieldCheck className="h-5 w-5 text-emerald-500 dark:text-emerald-400 mb-3" />, title: 'Evidence Integrity', desc: 'Deterministic SHA-256 sidecars (.meta.json), cryptographic hashes, and Merkle tree verification. Any byte alteration of exported evidence is detected immediately.' },
              { icon: <FileText className="h-5 w-5 text-blue-500 dark:text-blue-400 mb-3" />, title: 'Report Generation', desc: 'Generate forensic reports in HTML, Markdown, JSON, or terminal format from verified evidence bundles. Built-in suspicious finding detection and chain of custody documentation.' },
              { icon: <Lock className="h-5 w-5 text-blue-500 dark:text-blue-400 mb-3" />, title: 'Local-First Safety', desc: 'Read-only safety guarantees: no kernel hooking, no process injection, no persistence creation, no credential access. Fully functional in offline, classified environments.' },
            ].map((item) => (
              <div key={item.title} className="p-5 rounded border transition-all hover:shadow-md" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                {item.icon}
                <h3 className="text-sm font-bold mb-1.5 font-mono" style={{ color: 'var(--text)' }}>{item.title}</h3>
                <p className="text-xs leading-relaxed" style={{ color: 'var(--text-muted)' }}>{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Platform Roadmap */}
      <section className="py-14 border-b" style={{ backgroundColor: 'var(--page-bg-alt)', borderColor: 'var(--border)' }}>
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="mb-8">
            <h2 className="text-xl font-bold font-mono" style={{ color: 'var(--text)' }}>Compiler Status &amp; Roadmap</h2>
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              Transparent disclosure of current production components versus roadmap expansion.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {[
              { label: 'Current Core Subsystems', badge: 'AVAILABLE', badgeColor: 'bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border-emerald-500/30', items: ['✓ jocky DSL Parser, AST, Semantic Analyzer & IR', '✓ Linux standalone executable code generation and runtime collectors', '• Windows target and native collectors are currently stubs', '✓ CLI Toolchain (`check`, `compile`, `run`, `verify`, `fmt`, `hash`)', '✓ SHA-256 Sidecar Generation & Tamper Detection', '✓ Web IDE with Monaco Editor & Real Compiler Integration'] },
              { label: 'Compiler Enhancements', badge: 'IN DEVELOPMENT', badgeColor: 'bg-blue-500/20 text-blue-600 dark:text-blue-400 border-blue-500/30', items: ['• Windows native collectors (processes, registry, artifacts, ETW)', '• Linux ARM64 native compilation target', '• LLVM/Inkwell Direct Codegen (replacing Rust backend)', '• Cross-compilation from Linux to Windows via MinGW in CI', '• Additional report formats (CSV, Sigma rules export)'] },
              { label: 'Ecosystem & Integrations', badge: 'PLANNED', badgeColor: 'bg-amber-500/20 text-amber-600 dark:text-amber-400 border-amber-500/30', items: ['• Signed Cryptographic Tool Packages & Verifiable Attestations', '• Automated Forensic Timeline Reconstruction', '• IDE Language Server Protocol (LSP) Support', '• Package Manager for Shared Investigation Modules'] },
              { label: 'Research & Advanced Integrity', badge: 'RESEARCH', badgeColor: 'bg-slate-500/20 text-slate-500 dark:text-slate-400 border-slate-500/30', items: ['• Immutable Public Blockchain Anchoring (Ethereum/Polygon)', '• Zero-Knowledge Proofs for Redacted Evidence Verification', '• Advanced Memory Forensics & Anomaly Heuristics'] },
            ].map((block) => (
              <div key={block.label} className="p-4 rounded border" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold" style={{ color: 'var(--text)' }}>{block.label}</span>
                  <span className={`font-mono text-[10px] px-2 py-0.5 rounded border ${block.badgeColor}`}>
                    {block.badge}
                  </span>
                </div>
                <ul className="space-y-1.5" style={{ color: 'var(--text-muted)' }}>
                  {block.items.map((item) => <li key={item}>{item}</li>)}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Footer Section */}
      <section className="py-12 text-center" style={{ backgroundColor: 'var(--page-bg-dark)' }}>
        <div className="max-w-3xl mx-auto px-4">
          <h2 className="text-xl font-bold font-mono mb-2" style={{ color: 'var(--text)' }}>
            Start Authoring Forensic Investigations
          </h2>
          <p className="text-xs mb-6" style={{ color: 'var(--text-muted)' }}>
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
              className="inline-flex items-center gap-2 px-4 py-2 rounded font-medium text-xs transition-colors border"
              style={{ backgroundColor: 'var(--surface)', color: 'var(--text)', borderColor: 'var(--border)' }}
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