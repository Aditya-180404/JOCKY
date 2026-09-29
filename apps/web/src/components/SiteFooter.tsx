import { Link } from 'react-router-dom';
import { ShieldCheck, Terminal, Download, BookOpen, Code2 } from 'lucide-react';

export function SiteFooter() {
  return (
    <footer
      className="border-t text-xs"
      style={{ backgroundColor: 'var(--footer-bg)', borderColor: 'var(--border)', color: 'var(--text-muted)' }}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand Info */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <div className="h-6 w-6 rounded bg-blue-600 flex items-center justify-center font-mono font-bold text-white text-xs">
                JK
              </div>
              <span className="font-mono font-bold text-sm" style={{ color: 'var(--text)' }}>jocky</span>
            </div>
            <p className="leading-relaxed" style={{ color: 'var(--text-muted)' }}>
              Domain-specific forensic programming language and native compiler for verifiable digital investigations.
            </p>
            <div className="flex items-center gap-1.5 font-mono text-[11px]" style={{ color: 'var(--text)' }}>
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-500 dark:text-emerald-400" />
              <span>SHA-256 Verifiable Integrity</span>
            </div>
          </div>

          {/* Product Links */}
          <div>
            <h4 className="font-semibold text-xs uppercase tracking-wider mb-2.5" style={{ color: 'var(--text)' }}>Platform</h4>
            <ul className="space-y-1.5 text-xs">
              <li>
                <Link to="/ide" className="hover:text-blue-500 dark:hover:text-blue-400 transition-colors flex items-center gap-1.5">
                  <Terminal className="h-3 w-3" />
                  Web IDE
                </Link>
              </li>
              <li>
                <Link to="/download" className="hover:text-blue-500 dark:hover:text-blue-400 transition-colors flex items-center gap-1.5">
                  <Download className="h-3 w-3" />
                  Compiler Downloads
                </Link>
              </li>
              <li>
                <Link to="/examples" className="hover:text-blue-500 dark:hover:text-blue-400 transition-colors flex items-center gap-1.5">
                  <Code2 className="h-3 w-3" />
                  Canonical Examples
                </Link>
              </li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h4 className="font-semibold text-xs uppercase tracking-wider mb-2.5" style={{ color: 'var(--text)' }}>Documentation</h4>
            <ul className="space-y-1.5 text-xs">
              <li>
                <Link to="/guide" className="hover:text-blue-500 dark:hover:text-blue-400 transition-colors flex items-center gap-1.5">
                  <BookOpen className="h-3 w-3" />
                  Language Guide
                </Link>
              </li>
              <li>
                <Link to="/docs" className="hover:text-blue-500 dark:hover:text-blue-400 transition-colors">
                  CLI &amp; Compiler Architecture
                </Link>
              </li>
              <li>
                <Link to="/about" className="hover:text-blue-500 dark:hover:text-blue-400 transition-colors">
                  Security Model &amp; Threat Boundary
                </Link>
              </li>
            </ul>
          </div>

          {/* Supported Targets */}
          <div>
            <h4 className="font-semibold text-xs uppercase tracking-wider mb-2.5" style={{ color: 'var(--text)' }}>Supported Targets</h4>
            <ul className="space-y-1.5 text-[11px] font-mono">
              {[
                ['Windows x64 Native', 'Supported'],
                ['Linux x86_64 Native', 'Supported'],
                ['Web Compiler Sandbox', 'Online'],
              ].map(([platform, status]) => (
                <li key={platform} className="flex items-center justify-between">
                  <span style={{ color: 'var(--text-muted)' }}>{platform}</span>
                  <span className="text-emerald-600 dark:text-emerald-400 font-sans">{status}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div
          className="mt-8 pt-6 border-t flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px]"
          style={{ borderColor: 'var(--border)', color: 'var(--text-dim)' }}
        >
          <p>© 2026 jocky Project. Read-only digital forensics and verifiable chain of custody.</p>
          <div className="flex items-center gap-3">
            <Link to="/about" className="hover:text-blue-500 dark:hover:text-blue-400 transition-colors">Read-Only Safety Guarantee</Link>
            <span>•</span>
            <Link to="/docs" className="hover:text-blue-500 dark:hover:text-blue-400 transition-colors">Integrity Specification</Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
