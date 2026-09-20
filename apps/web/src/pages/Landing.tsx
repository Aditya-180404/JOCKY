import { Link } from 'react-router-dom';
import { Activity, Terminal, Database, Shield, CheckCircle, Code, FileText, Search } from 'lucide-react';

export function Landing() {
  const features = [
    {
      icon: Terminal,
      title: 'Domain-Specific Language',
      description: 'Write forensic investigations in a purpose-built DSL designed for evidence collection, not general programming.',
    },
    {
      icon: Code,
      title: 'Web-Based IDE',
      description: 'Full-featured editor with syntax highlighting, validation, and real-time diagnostics - all in your browser.',
    },
    {
      icon: Database,
      title: 'Tool Repository',
      description: 'Version, publish, and share forensic tools with your team. Complete with capability tracking and SBOMs.',
    },
    {
      icon: FileText,
      title: 'Investigation Management',
      description: 'Create and track investigations, associate tools, and manage evidence collection workflows.',
    },
    {
      icon: Search,
      title: 'Evidence Integrity',
      description: 'Automatic SHA-256 hashing, Merkle tree batching, and optional blockchain anchoring for tamper-proof evidence.',
    },
    {
      icon: Shield,
      title: 'Security First',
      description: 'RBAC, audit logging, multi-tenancy, and sandboxed compilation. Built for defensive forensics.',
    },
  ];

  return (
    <div className="min-h-screen bg-forensic-950">
      {/* Hero Section */}
      <section className="relative overflow-hidden py-20 lg:py-32">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-from)_0%,_transparent_70%)] from-accent-blue/10 via-transparent to-transparent" />
        <div className="relative max-w-7xl mx-auto px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-accent-blue/10 border border-accent-blue/20 text-accent-blue text-sm font-medium mb-6 animate-fade-in">
              <Activity className="h-4 w-4" />
              <span>TraceForge v0.1.0 - Digital Forensics Platform</span>
            </div>
            <h1 className="text-4xl lg:text-6xl font-bold text-forensic-100 mb-6 animate-slide-up">
              Build Forensic Tools <br />
              <span className="text-accent-blue">That Stand Up in Court</span>
            </h1>
            <p className="text-lg lg:text-xl text-forensic-400 mb-8 max-w-2xl mx-auto animate-slide-up" style={{ animationDelay: '100ms' }}>
              TraceForge is a cloud-based platform for developing, compiling, and distributing digital forensic investigation tools.
              Write once in our domain-specific language, compile to native binaries, and deploy with cryptographic integrity guarantees.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-slide-up" style={{ animationDelay: '200ms' }}>
              <Link to="/register" className="btn-primary btn-lg gap-2">
                <Activity className="h-5 w-5" />
                Start Free
              </Link>
              <Link to="/editor" className="btn-secondary btn-lg gap-2">
                <Terminal className="h-5 w-5" />
                Try the IDE
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 lg:py-28 border-y border-forensic-900">
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl lg:text-4xl font-bold text-forensic-100 mb-4">Built for Digital Forensics</h2>
            <p className="text-forensic-400 text-lg max-w-2xl mx-auto">
              Every feature designed around the needs of forensic investigators and incident responders.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => (
              <article
                key={feature.title}
                className="card-hover p-6 animate-fade-in"
                style={{ animationDelay: `${index * 100}ms` }}
              >
                <div className="h-12 w-12 rounded-lg bg-accent-blue/10 flex items-center justify-center mb-4">
                  <feature.icon className="h-7 w-7 text-accent-blue" />
                </div>
                <h3 className="text-xl font-semibold text-forensic-100 mb-2">{feature.title}</h3>
                <p className="text-forensic-400">{feature.description}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* Language Example */}
      <section className="py-20 lg:py-28">
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-8 items-center">
            <div>
              <h2 className="text-3xl lg:text-4xl font-bold text-forensic-100 mb-4">TraceForge Language</h2>
              <p className="text-forensic-400 mb-6">
                Our domain-specific language is purpose-built for forensic collection.
                No general-purpose complexity - just the operations you need.
              </p>
              <ul className="space-y-3">
                {[
                  'Collect system info, processes, network connections, files, and logs',
                  'Filter and limit results with expressive syntax',
                  'Export evidence in JSON, CSV, or XML formats',
                  'Automatic capability tracking for compliance',
                  'Reproducible, deterministic compilation',
                ].map((item, i) => (
                  <li key={i} className="flex items-center gap-3 text-forensic-300">
                    <CheckCircle className="h-5 w-5 text-accent-green flex-shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="card p-6">
              <div className="flex items-center gap-2 mb-4">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-red-500" />
                  <div className="w-3 h-3 rounded-full bg-amber-500" />
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                </div>
                <span className="text-sm text-forensic-500 font-mono">process_triage.tfg</span>
              </div>
              <pre className="code-block text-forensic-300 overflow-x-auto"><code>{`investigation "process_triage" {
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
}`}</code></pre>
            </div>
          </div>
        </div>
      </section>

      {/* Compilation Pipeline */}
      <section className="py-20 lg:py-28 border-y border-forensic-900 bg-forensic-900/30">
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl lg:text-4xl font-bold text-forensic-100 mb-4">Complete Compilation Pipeline</h2>
            <p className="text-forensic-400 text-lg max-w-2xl mx-auto">
              From source to signed artifact with full reproducibility metadata.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <div className="card p-6 text-center">
              <div className="h-16 w-16 rounded-xl bg-blue-500/10 flex items-center justify-center mx-auto mb-4">
                <Code className="h-8 w-8 text-accent-blue" />
              </div>
              <h3 className="text-xl font-semibold text-forensic-100 mb-2">1. Write &amp; Validate</h3>
              <p className="text-forensic-400">Write investigations in the web IDE with real-time syntax checking and semantic validation.</p>
            </div>
            <div className="card p-6 text-center">
              <div className="h-16 w-16 rounded-xl bg-green-500/10 flex items-center justify-center mx-auto mb-4">
                <Terminal className="h-8 w-8 text-accent-green" />
              </div>
              <h3 className="text-xl font-semibold text-forensic-100 mb-2">2. Compile</h3>
              <p className="text-forensic-400">Compile to native Linux ELF or Windows PE binaries with LLVM backend optimization.</p>
            </div>
            <div className="card p-6 text-center">
              <div className="h-16 w-16 rounded-xl bg-purple-500/10 flex items-center justify-center mx-auto mb-4">
                <Shield className="h-8 w-8 text-accent-purple" />
              </div>
              <h3 className="text-xl font-semibold text-forensic-100 mb-2">3. Verify &amp; Publish</h3>
              <p className="text-forensic-400">SHA-256 hashing, capability manifests, SBOM generation, and signed repository publishing.</p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 lg:py-28">
        <div className="max-w-3xl mx-auto px-6 lg:px-8 text-center">
          <div className="card p-8 lg:p-12 border-accent-blue/30 bg-accent-blue/5">
            <h2 className="text-3xl lg:text-4xl font-bold text-forensic-100 mb-4">Ready to Build Better Forensic Tools?</h2>
            <p className="text-forensic-400 mb-8 max-w-xl mx-auto">
              Join investigators and developers using TraceForge to create reproducible, auditable forensic investigation tools.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link to="/register" className="btn-primary btn-lg gap-2">
                <Activity className="h-5 w-5" />
                Create Free Account
              </Link>
              <Link to="/editor" className="btn-secondary btn-lg gap-2 border-accent-blue text-accent-blue hover:bg-accent-blue/10">
                <Terminal className="h-5 w-5" />
                Explore the IDE
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-forensic-900">
        <div className="max-w-7xl mx-auto px-6 lg:px-8 text-center">
          <p className="text-forensic-500 text-sm">
            TraceForge - Defensive Digital Forensics Platform
            <br />
            Built with Rust, React, and LLVM
          </p>
        </div>
      </footer>
    </div>
  );
}