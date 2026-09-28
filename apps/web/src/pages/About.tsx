import { SiteHeader } from '../components/SiteHeader';
import { SiteFooter } from '../components/SiteFooter';
import { ShieldCheck, CheckCircle2 } from 'lucide-react';

export function AboutPage() {
  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 flex flex-col font-sans">
      <SiteHeader />

      <main className="flex-1 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-14 w-full space-y-10">
        <div className="text-center space-y-3">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-mono">
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Forensic Safety & Integrity Standards</span>
          </div>
          <h1 className="text-3xl font-bold font-mono text-white">
            About jocky
          </h1>
          <p className="text-xs text-slate-400 max-w-2xl mx-auto leading-relaxed">
            jocky bridges the gap between digital forensic rigor and modern declarative programming languages.
          </p>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 rounded p-6 sm:p-8 space-y-5 text-xs text-slate-300 leading-relaxed">
          <h2 className="text-base font-bold font-mono text-white">Core Architecture & Principles</h2>
          <p>
            Traditional digital triage often relies on brittle shell scripts, inconsistent data formats, and manual verification steps that can compromise the forensic chain of custody.
          </p>
          <p>
            <strong>jocky enforces structural guarantees:</strong>
          </p>
          <ul className="space-y-3 pl-2">
            <li className="flex items-start gap-2.5">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <span><strong>Formal Language Grammar:</strong> Every triage operation is written in clean, readable, validated syntax with capability inference.</span>
            </li>
            <li className="flex items-start gap-2.5">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <span><strong>Deterministic Execution:</strong> Collector modules run with minimal footprint, read-only permissions, and zero persistence or kernel manipulation.</span>
            </li>
            <li className="flex items-start gap-2.5">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <span><strong>Immutable Evidence Chains:</strong> Cryptographic SHA-256 digests and metadata sidecars are automatically computed for non-repudiation.</span>
            </li>
          </ul>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
