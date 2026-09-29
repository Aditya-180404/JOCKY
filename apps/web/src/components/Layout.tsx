import { useState } from 'react';
import { Outlet, NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  LayoutDashboard,
  Terminal,
  Database,
  FileText,
  Search,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Shield,
  Activity,
  Menu,
} from 'lucide-react';
import clsx from 'clsx';

const navigation = [
  { name: 'Dashboard',     href: '/dashboard',     icon: LayoutDashboard },
  { name: 'IDE',           href: '/editor',         icon: Terminal },
  { name: 'Repository',    href: '/repository',     icon: Database },
  { name: 'Investigations',href: '/investigations', icon: FileText },
  { name: 'Evidence',      href: '/evidence',       icon: Search },
];

const adminNavigation = [
  { name: 'Admin', href: '/admin', icon: Shield },
];

export function Layout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen]   = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const isActive = (href: string) =>
    location.pathname === href || location.pathname.startsWith(href + '/');

  const SidebarContent = ({ mobile = false }: { mobile?: boolean }) => (
    <>
      <div className="flex h-16 items-center justify-between px-4 border-b border-forensic-800">
        <NavLink to="/dashboard" className="flex items-center gap-2" title="JOCKY">
          <Activity className="h-8 w-8 text-accent-blue" />
          <span className={clsx(
            'font-bold text-lg text-forensic-100 transition-opacity',
            mobile ? 'opacity-100' : (sidebarOpen ? 'opacity-100' : 'opacity-0')
          )}>
            JOCKY
          </span>
        </NavLink>
        {!mobile && (
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors"
            aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {sidebarOpen ? <ChevronLeft className="h-5 w-5" /> : <ChevronRight className="h-5 w-5" />}
          </button>
        )}
        {mobile && (
          <button
            onClick={() => setMobileMenuOpen(false)}
            className="p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors"
            aria-label="Close menu"
          >
            <ChevronLeft className="h-5 w-5" />
          </button>
        )}
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" role="navigation" aria-label="Main navigation">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            onClick={() => mobile && setMobileMenuOpen(false)}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150',
                isActive
                  ? 'bg-forensic-800 text-accent-blue'
                  : 'text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800/50',
                !mobile && !sidebarOpen && 'justify-center px-2'
              )
            }
            title={(!mobile && !sidebarOpen) ? item.name : undefined}
          >
            <item.icon className="h-5 w-5 flex-shrink-0" aria-hidden="true" />
            {(mobile || sidebarOpen) && <span>{item.name}</span>}
          </NavLink>
        ))}

        {user?.role === 'ADMIN' && (
          <div className="pt-4 mt-4 border-t border-forensic-800">
            <p className="px-3 text-xs font-semibold text-forensic-500 uppercase tracking-wider">
              Administration
            </p>
            {adminNavigation.map((item) => (
              <NavLink
                key={item.name}
                to={item.href}
                onClick={() => mobile && setMobileMenuOpen(false)}
                className={({ isActive }) =>
                  clsx(
                    'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150',
                    isActive
                      ? 'bg-forensic-800 text-accent-purple'
                      : 'text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800/50',
                    !mobile && !sidebarOpen && 'justify-center px-2'
                  )
                }
                title={(!mobile && !sidebarOpen) ? item.name : undefined}
              >
                <item.icon className="h-5 w-5 flex-shrink-0" aria-hidden="true" />
                {(mobile || sidebarOpen) && <span>{item.name}</span>}
              </NavLink>
            ))}
          </div>
        )}
      </nav>

      <div className="p-3 border-t border-forensic-800">
        <div className={clsx('flex items-center gap-3 px-3 py-2 rounded-lg', (!mobile && !sidebarOpen) && 'justify-center')}>
          <div className={clsx('w-8 h-8 rounded-full bg-accent-blue/20 flex items-center justify-center flex-shrink-0', (!mobile && !sidebarOpen) && 'mx-auto')}>
            <span className="text-sm font-medium text-accent-blue">
              {user?.email?.charAt(0).toUpperCase() || 'U'}
            </span>
          </div>
          {(mobile || sidebarOpen) && (
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-forensic-100 truncate">{user?.email}</p>
              <p className="text-xs text-forensic-500 capitalize">{user?.role?.toLowerCase()}</p>
            </div>
          )}
        </div>
        <button
          onClick={logout}
          className={clsx(
            'mt-3 w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-forensic-400 hover:text-accent-red hover:bg-forensic-800/50 transition-colors',
            (!mobile && !sidebarOpen) && 'justify-center px-2'
          )}
          title={(!mobile && !sidebarOpen) ? 'Log out' : ''}
        >
          <LogOut className="h-5 w-5 flex-shrink-0" aria-hidden="true" />
          {(mobile || sidebarOpen) && <span>Log out</span>}
        </button>
      </div>
    </>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      {/* ── Desktop Sidebar (hidden on mobile) ── */}
      <aside
        className={clsx(
          'sidebar flex-col hidden lg:flex',
          sidebarOpen ? '' : 'sidebar-collapsed'
        )}
      >
        <SidebarContent />
      </aside>

      {/* ── Mobile Sidebar overlay ── */}
      {mobileMenuOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/60 z-40 lg:hidden"
            onClick={() => setMobileMenuOpen(false)}
            aria-hidden="true"
          />
          {/* Drawer */}
          <aside className="fixed inset-y-0 left-0 z-50 w-64 sidebar flex flex-col lg:hidden">
            <SidebarContent mobile />
          </aside>
        </>
      )}

      {/* ── Main content ── */}
      <main className={clsx('main-content flex-1 flex flex-col min-w-0', sidebarOpen ? '' : 'main-content-expanded')}>
        {/* Header */}
        <header className="header flex items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-4">
            {/* Mobile hamburger */}
            <button
              id="mobile-sidebar-toggle"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 rounded-lg text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800 transition-colors"
              aria-label="Open menu"
            >
              <Menu className="h-6 w-6" />
            </button>
            <h1 className="text-xl font-semibold text-forensic-100 hidden sm:block">
              {navigation.find((n) => isActive(n.href))?.name || 'JOCKY'}
            </h1>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-forensic-800/50 rounded-lg border border-forensic-700">
              <Shield className="h-4 w-4 text-accent-green" />
              <span className="text-sm text-forensic-300">Secured</span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <div className="flex-1 p-4 sm:p-6 overflow-auto">
          <Outlet />
        </div>
      </main>
    </div>
  );
}