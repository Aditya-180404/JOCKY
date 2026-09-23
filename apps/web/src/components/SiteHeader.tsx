import { NavLink, Link } from 'react-router-dom';
import { Terminal, Download, BookOpen, Code2, FileText, Info } from 'lucide-react';
import clsx from 'clsx';

export function SiteHeader() {
  const navLinks = [
    { name: 'Overview', href: '/' },
    { name: 'Web IDE', href: '/ide', icon: Terminal },
    { name: 'Download', href: '/download', icon: Download },
    { name: 'Language Guide', href: '/guide', icon: BookOpen },
    { name: 'Examples', href: '/examples', icon: Code2 },
    { name: 'Documentation', href: '/docs', icon: FileText },
    { name: 'Architecture', href: '/about', icon: Info },
  ];

  return (
    <header className="sticky top-0 z-50 border-b border-forensic-800 bg-[#0d131f] text-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
        {/* Brand Logo */}
        <Link to="/" className="flex items-center gap-2.5">
          <div className="h-7 w-7 rounded bg-blue-600 flex items-center justify-center font-mono font-bold text-white text-xs">
            TF
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono font-bold text-sm tracking-wider text-slate-100">
              TRACEFORGE
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              v0.1.0
            </span>
          </div>
        </Link>

        {/* Navigation Links */}
        <nav className="hidden md:flex items-center gap-1" aria-label="Main Navigation">
          {navLinks.map((link) => (
            <NavLink
              key={link.name}
              to={link.href}
              className={({ isActive }) =>
                clsx(
                  'px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5',
                  isActive
                    ? 'bg-slate-800 text-blue-400 border border-slate-700'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                )
              }
            >
              {link.icon && <link.icon className="h-3.5 w-3.5" />}
              {link.name}
            </NavLink>
          ))}
        </nav>

        {/* Header Action Buttons */}
        <div className="flex items-center gap-2.5">
          <Link
            to="/ide"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-blue-600 text-white hover:bg-blue-700 transition-colors"
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>Launch Web IDE</span>
          </Link>
          <Link
            to="/download"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <Download className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Download</span>
          </Link>
        </div>
      </div>
    </header>
  );
}
