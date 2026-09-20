import { useEffect, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import {
  User,
  Mail,
  Lock,
  Building,
  Shield,
  Save,
  Loader2,
  CheckCircle,
  AlertCircle,
} from 'lucide-react';
import clsx from 'clsx';

export function Settings() {
  const { user, refreshUser } = useAuth();
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'organization'>('profile');
  const [profile, setProfile] = useState({ fullName: '', email: '' });
  const [password, setPassword] = useState({ current: '', new: '', confirm: '' });
  const [organization, setOrganization] = useState({ name: '', slug: '' });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    if (user) {
      setProfile({ fullName: user.full_name || '', email: user.email });
    }
  }, [user]);

  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 5000);
  };

  const handleProfileSave = async () => {
    setLoading(true);
    try {
      // In a real implementation, this would call an API endpoint
      await new Promise(resolve => setTimeout(resolve, 500));
      showMessage('success', 'Profile updated successfully');
    } catch {
      showMessage('error', 'Failed to update profile');
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async () => {
    if (password.new !== password.confirm) {
      showMessage('error', 'New passwords do not match');
      return;
    }
    if (password.new.length < 8) {
      showMessage('error', 'Password must be at least 8 characters');
      return;
    }
    setLoading(true);
    try {
      // In a real implementation, this would call an API endpoint
      await new Promise(resolve => setTimeout(resolve, 500));
      setPassword({ current: '', new: '', confirm: '' });
      showMessage('success', 'Password changed successfully');
    } catch {
      showMessage('error', 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  const handleOrgSave = async () => {
    setLoading(true);
    try {
      // In a real implementation, this would call an API endpoint
      await new Promise(resolve => setTimeout(resolve, 500));
      showMessage('success', 'Organization updated successfully');
    } catch {
      showMessage('error', 'Failed to update organization');
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'organization', label: 'Organization', icon: Building },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-forensic-100">Settings</h1>
        <p className="text-forensic-400 mt-1">Manage your account and preferences</p>
      </div>

      {/* Message */}
      {message && (
        <div className={clsx('p-4 rounded-lg flex items-center gap-3 animate-slide-down',
          message.type === 'success' && 'bg-green-500/10 border border-green-500/20 text-green-400',
          message.type === 'error' && 'bg-red-500/10 border border-red-500/20 text-red-400'
        )}>
          {message.type === 'success' ? <CheckCircle className="h-5 w-5 flex-shrink-0" /> : <AlertCircle className="h-5 w-5 flex-shrink-0" />}
          <p>{message.text}</p>
        </div>
      )}

      {/* Tabs */}
      <div className="card">
        <div className="border-b border-forensic-800">
          <nav className="flex gap-1 p-1" role="tablist">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                role="tab"
                aria-selected={activeTab === tab.id}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={clsx(
                  'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  activeTab === tab.id
                    ? 'bg-forensic-800 text-forensic-100'
                    : 'text-forensic-400 hover:text-forensic-100 hover:bg-forensic-800/50'
                )}
              >
                <tab.icon className="h-4 w-4 inline mr-1" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Profile Tab */}
        {activeTab === 'profile' && (
          <div className="p-6 max-w-2xl">
            <h2 className="text-lg font-semibold text-forensic-100 mb-6">Profile Information</h2>
            <div className="space-y-5">
              <div>
                <label htmlFor="fullName" className="label">Full Name</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                  <input
                    id="fullName"
                    type="text"
                    value={profile.fullName}
                    onChange={(e) => setProfile(p => ({ ...p, fullName: e.target.value }))}
                    className="input pl-10"
                    placeholder="John Doe"
                  />
                </div>
              </div>
              <div>
                <label htmlFor="email" className="label">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                  <input
                    id="email"
                    type="email"
                    value={profile.email}
                    onChange={(e) => setProfile(p => ({ ...p, email: e.target.value }))}
                    className="input pl-10"
                    placeholder="you@organization.com"
                  />
                </div>
              </div>
              <div>
                <label htmlFor="role" className="label">Role</label>
                <div className="relative">
                  <Shield className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                  <input
                    id="role"
                    type="text"
                    value={user?.role || 'INVESTIGATOR'}
                    className="input pl-10 bg-forensic-900 cursor-not-allowed"
                    readOnly
                  />
                </div>
                <p className="mt-1 text-xs text-forensic-500">Role is assigned by organization administrators</p>
              </div>
              <button onClick={handleProfileSave} disabled={loading} className="btn-primary gap-2">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                {loading ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        )}

        {/* Security Tab */}
        {activeTab === 'security' && (
          <div className="p-6 max-w-2xl">
            <h2 className="text-lg font-semibold text-forensic-100 mb-6">Change Password</h2>
            <div className="space-y-5">
              <div>
                <label htmlFor="currentPassword" className="label">Current Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                  <input
                    id="currentPassword"
                    type="password"
                    value={password.current}
                    onChange={(e) => setPassword(p => ({ ...p, current: e.target.value }))}
                    className="input pl-10"
                    placeholder="••••••••"
                  />
                </div>
              </div>
              <div>
                <label htmlFor="newPassword" className="label">New Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                  <input
                    id="newPassword"
                    type="password"
                    value={password.new}
                    onChange={(e) => setPassword(p => ({ ...p, new: e.target.value }))}
                    className="input pl-10"
                    placeholder="••••••••"
                    minLength={8}
                  />
                </div>
                <p className="mt-1 text-xs text-forensic-500">Must be at least 8 characters</p>
              </div>
              <div>
                <label htmlFor="confirmPassword" className="label">Confirm New Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                  <input
                    id="confirmPassword"
                    type="password"
                    value={password.confirm}
                    onChange={(e) => setPassword(p => ({ ...p, confirm: e.target.value }))}
                    className="input pl-10"
                    placeholder="••••••••"
                  />
                </div>
              </div>
              <button onClick={handlePasswordChange} disabled={loading} className="btn-primary gap-2">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                {loading ? 'Changing...' : 'Change Password'}
              </button>
            </div>
          </div>
        )}

        {/* Organization Tab */}
        {activeTab === 'organization' && (
          <div className="p-6 max-w-2xl">
            <h2 className="text-lg font-semibold text-forensic-100 mb-6">Organization Settings</h2>
            <p className="text-forensic-400 mb-6">Only organization administrators can modify these settings</p>
            <div className="space-y-5">
              <div>
                <label htmlFor="orgName" className="label">Organization Name</label>
                <div className="relative">
                  <Building className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                  <input
                    id="orgName"
                    type="text"
                    value={organization.name}
                    onChange={(e) => setOrganization(p => ({ ...p, name: e.target.value }))}
                    className="input pl-10"
                    placeholder="Acme Corporation"
                    disabled={user?.role !== 'ADMIN'}
                  />
                </div>
              </div>
              <div>
                <label htmlFor="orgSlug" className="label">Organization Slug</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-forensic-500 text-sm font-mono">traceforge.io/</span>
                  <input
                    id="orgSlug"
                    type="text"
                    value={organization.slug}
                    onChange={(e) => setOrganization(p => ({ ...p, slug: e.target.value }))}
                    className="input pl-28"
                    placeholder="acme-corp"
                    pattern="[a-z0-9-]+"
                    disabled={user?.role !== 'ADMIN'}
                  />
                </div>
                <p className="mt-1 text-xs text-forensic-500">Lowercase, numbers, and hyphens only</p>
              </div>
              <button onClick={handleOrgSave} disabled={loading || user?.role !== 'ADMIN'} className="btn-primary gap-2">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                {loading ? 'Saving...' : 'Save Changes'}
              </button>
              {user?.role !== 'ADMIN' && (
                <p className="text-xs text-forensic-500">Only administrators can modify organization settings</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}