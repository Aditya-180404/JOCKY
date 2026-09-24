import { Link } from 'react-router-dom';
import { ShieldCheck, Terminal, Download, BookOpen, Code2 } from 'lucide-react';

export function SiteFooter() {
  return (
    <footer className="border-t border-slate-800 bg-[#0a0e17] text-slate-400 text-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand Info */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <div className="h-6 w-6 rounded bg-blue-600 flex items-center justify-center font-mono font-bold text-white text-xs">
                JK
              </div>
              <span className="font-mono font-bold text-slate-100 text-sm">JOCKY</span>
            </div>
            <p className="text-slate-400 leading-relaxed text-xs">
              Domain-specific forensic programming language and native compiler for verifiable digital investigations.
            </p>
            <div className="flex items-center gap-1.5 text-slate-300 font-mono text-[11px]">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
              <span>SHA-256 Verifiable Integrity</span>
            </div>
          </div>

          {/* Product Links */}
          <div>
            <h4 className="font-semibold text-slate-200 text-xs uppercase tracking-wider mb-2.5">Platform</h4>
            <ul className="space-y-1.5 text-xs">
              <li>
                <Link to="/ide" className="hover:text-blue-400 transition-colors flex items-center gap-1.5">
                  <Terminal className="h-3 w-3" />
                  Web IDE
                </Link>
              </li>
              <li>
                <Link to="/download" className="hover:text-blue-400 transition-colors flex items-center gap-1.5">
                  <Download className="h-3 w-3" />
                  Compiler Downloads
                </Link>
              </li>
              <li>
                <Link to="/examples" className="hover:text-blue-400 transition-colors flex items-center gap-1.5">
                  <Code2 className="h-3 w-3" />
                  Canonical Examples
                </Link>
              </li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h4 className="font-semibold text-slate-200 text-xs uppercase tracking-wider mb-2.5">Documentation</h4>
            <ul className="space-y-1.5 text-xs">
              <li>
                <Link to="/guide" className="hover:text-blue-400 transition-colors flex items-center gap-1.5">
                  <BookOpen className="h-3 w-3" />
                  Language Guide
                </Link>
              </li>
              <li>
                <Link to="/docs" className="hover:text-blue-400 transition-colors">
                  CLI & Compiler Architecture
                </Link>
              </li>
              <li>
                <Link to="/about" className="hover:text-blue-400 transition-colors">
                  Security Model & Threat Boundary
                </Link>
              </li>
            </ul>
          </div>

          {/* Supported Targets */}
          <div>
            <h4 className="font-semibold text-slate-200 text-xs uppercase tracking-wider mb-2.5">Supported Targets</h4>
            <ul className="space-y-1.5 text-[11px] font-mono text-slate-400">
              <li className="flex items-center justify-between">
                <span>Windows x64 Native</span>
                <span className="text-emerald-400 font-sans">Supported</span>
              </li>
              <li className="flex items-center justify-between">
                <span>Linux x86_64 Native</span>
                <span className="text-emerald-400 font-sans">Supported</span>
              </li>
              <li className="flex items-center justify-between">
                <span>Web Compiler Sandbox</span>
                <span className="text-emerald-400 font-sans">Online</span>
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-8 pt-6 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-3 text-slate-500 text-[11px]">
          <p>© 2026 JOCKY Project. Read-only digital forensics and verifiable chain of custody.</p>
          <div className="flex items-center gap-3">
            <Link to="/about" className="hover:text-slate-300">Read-Only Safety Guarantee</Link>
            <span>•</span>
            <Link to="/docs" className="hover:text-slate-300">Integrity Specification</Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
