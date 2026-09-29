import { useState } from 'react';
import { NavLink, Link } from 'react-router-dom';
import { Terminal, Download, BookOpen, Code2, FileText, Library, Menu, X, Sun, Moon } from 'lucide-react';
import clsx from 'clsx';
import { useTheme } from '../contexts/ThemeContext';

export function SiteHeader() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { theme, toggleTheme } = useTheme();

  const navLinks = [
    { name: 'Overview',       href: '/' },
    { name: 'Web IDE',        href: '/ide',       icon: Terminal },
    { name: 'Download',       href: '/download',  icon: Download },
    { name: 'Language Guide', href: '/guide',     icon: BookOpen },
    { name: 'Examples',       href: '/examples',  icon: Code2 },
    { name: 'Playbooks',      href: '/playbooks', icon: Library },
    { name: 'Documentation',  href: '/docs',      icon: FileText },
  ];

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    clsx(
      'px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5',
      isActive
        ? 'bg-blue-600/15 text-blue-500 dark:text-blue-400 border border-blue-500/30'
        : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800/60'
    );

  return (
    <header
      className="sticky top-0 z-50 border-b"
      style={{ backgroundColor: 'var(--header-bg)', borderColor: 'var(--header-border)' }}
    >
      {/* ─── Desktop bar ─── */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-4">
        {/* Brand Logo */}
        <Link to="/" className="flex items-center gap-2.5 flex-shrink-0">
          <div className="h-7 w-7 rounded bg-blue-600 flex items-center justify-center font-mono font-bold text-white text-xs shadow-sm">
            JK
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono font-bold text-sm tracking-wider" style={{ color: 'var(--text)' }}>
              jocky
            </span>
            <span
              className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
              style={{ backgroundColor: 'var(--surface-muted)', color: 'var(--text-muted)', borderColor: 'var(--border)' }}
            >
              v0.1.0
            </span>
          </div>
        </Link>

        {/* Desktop Navigation — hidden below md */}
        <nav className="hidden md:flex items-center gap-1 flex-1 justify-center" aria-label="Main Navigation">
          {navLinks.map((link) => (
            <NavLink
              key={link.name}
              to={link.href}
              end={link.href === '/'}
              className={navLinkClass}
            >
              {link.icon && <link.icon className="h-3.5 w-3.5" />}
              {link.name}
            </NavLink>
          ))}
        </nav>

        {/* Right-side actions */}
        <div className="flex items-center gap-2">
          {/* Theme toggle */}
          <button
            id="theme-toggle"
            onClick={toggleTheme}
            className="theme-toggle"
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            title={theme === 'dark' ? 'Light mode' : 'Dark mode'}
          >
            {theme === 'dark'
              ? <Sun className="h-4 w-4" />
              : <Moon className="h-4 w-4" />
            }
          </button>

          {/* Desktop CTA buttons — hidden below md */}
          <div className="hidden md:flex items-center gap-2">
            <Link
              to="/ide"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-blue-600 text-white hover:bg-blue-700 transition-colors shadow-sm"
            >
              <Terminal className="h-3.5 w-3.5" />
              <span>Launch Web IDE</span>
            </Link>
            <Link
              to="/download"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors border"
              style={{ backgroundColor: 'var(--surface-muted)', color: 'var(--text)', borderColor: 'var(--border)' }}
            >
              <Download className="h-3.5 w-3.5" />
              <span>Download</span>
            </Link>
          </div>

          {/* Mobile hamburger */}
          <button
            id="mobile-menu-toggle"
            onClick={() => setMobileOpen((o) => !o)}
            className="md:hidden p-2 rounded-lg transition-colors"
            style={{ color: 'var(--text-muted)' }}
            aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={mobileOpen}
          >
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {/* ─── Mobile drawer ─── */}
      {mobileOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 top-14 bg-black/50 z-40 md:hidden"
            onClick={() => setMobileOpen(false)}
            aria-hidden="true"
          />
          {/* Slide-down panel */}
          <nav
            className="absolute left-0 right-0 top-14 z-50 border-b md:hidden shadow-lg"
            style={{ backgroundColor: 'var(--header-bg)', borderColor: 'var(--border)' }}
            aria-label="Mobile Navigation"
          >
            <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 space-y-1">
              {navLinks.map((link) => (
                <NavLink
                  key={link.name}
                  to={link.href}
                  end={link.href === '/'}
                  onClick={() => setMobileOpen(false)}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center gap-2.5 px-3 py-2.5 rounded text-sm font-medium transition-colors',
                      isActive
                        ? 'bg-blue-600/10 text-blue-500 dark:text-blue-400 border border-blue-500/30'
                        : 'hover:bg-slate-100 dark:hover:bg-slate-800/60'
                    )
                  }
                  style={{ color: 'var(--text-muted)' }}
                >
                  {link.icon && <link.icon className="h-4 w-4 flex-shrink-0" />}
                  {link.name}
                </NavLink>
              ))}

              {/* Mobile CTAs */}
              <div className="pt-3 pb-1 flex flex-col sm:flex-row gap-2 border-t" style={{ borderColor: 'var(--border)' }}>
                <Link
                  to="/ide"
                  onClick={() => setMobileOpen(false)}
                  className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 transition-colors"
                >
                  <Terminal className="h-4 w-4" />
                  Launch Web IDE
                </Link>
                <Link
                  to="/download"
                  onClick={() => setMobileOpen(false)}
                  className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded text-sm font-medium transition-colors border"
                  style={{ backgroundColor: 'var(--surface-muted)', color: 'var(--text)', borderColor: 'var(--border)' }}
                >
                  <Download className="h-4 w-4" />
                  Download Compiler
                </Link>
              </div>
            </div>
          </nav>
        </>
      )}
    </header>
  );
}
