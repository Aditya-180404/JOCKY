import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Activity, Mail, Lock, User, Building, AlertCircle, Eye, EyeOff, Loader2 } from 'lucide-react';

export function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    fullName: '',
    organizationName: '',
    organizationSlug: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);

    try {
      await register({
        email: formData.email,
        password: formData.password,
        full_name: formData.fullName || undefined,
        organization_name: formData.organizationName,
        organization_slug: formData.organizationSlug,
      });
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-forensic-950">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 mb-6">
            <Activity className="h-10 w-10 text-accent-blue" />
            <span className="text-2xl font-bold text-forensic-100">TraceForge</span>
          </Link>
          <h1 className="text-2xl font-bold text-forensic-100 mb-2">Create your account</h1>
          <p className="text-forensic-400">Start building forensic tools today</p>
        </div>

        <div className="card p-6 lg:p-8">
          {error && (
            <div className="mb-6 p-4 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center gap-3 text-red-400 animate-fade-in">
              <AlertCircle className="h-5 w-5 flex-shrink-0" />
              <p className="text-sm">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="fullName" className="label">Full Name</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                  <input
                    id="fullName"
                    name="fullName"
                    type="text"
                    value={formData.fullName}
                    onChange={handleChange}
                    className="input pl-10"
                    placeholder="John Doe"
                    autoComplete="name"
                    disabled={loading}
                  />
                </div>
              </div>
              <div>
                <label htmlFor="email" className="label">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                  <input
                    id="email"
                    name="email"
                    type="email"
                    value={formData.email}
                    onChange={handleChange}
                    className="input pl-10"
                    placeholder="you@org.com"
                    required
                    autoComplete="email"
                    disabled={loading}
                  />
                </div>
              </div>
            </div>

            <div>
              <label htmlFor="organizationName" className="label">Organization Name</label>
              <div className="relative">
                <Building className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                <input
                  id="organizationName"
                  name="organizationName"
                  type="text"
                  value={formData.organizationName}
                  onChange={handleChange}
                  className="input pl-10"
                  placeholder="Acme Corp"
                  required
                  autoComplete="organization"
                  disabled={loading}
                />
              </div>
            </div>

            <div>
              <label htmlFor="organizationSlug" className="label">Organization Slug</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-forensic-500 text-sm font-mono">traceforge.io/</span>
                <input
                  id="organizationSlug"
                  name="organizationSlug"
                  type="text"
                  value={formData.organizationSlug}
                  onChange={handleChange}
                  className="input pl-28"
                  placeholder="acme-corp"
                  required
                  pattern="[a-z0-9\-]+"
                  disabled={loading}
                />
              </div>
              <p className="mt-1 text-xs text-forensic-500">Lowercase, numbers, and hyphens only</p>
            </div>

            <div>
              <label htmlFor="password" className="label">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={formData.password}
                  onChange={handleChange}
                  className="input pl-10 pr-10"
                  placeholder="••••••••"
                  required
                  autoComplete="new-password"
                  minLength={8}
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-forensic-500 hover:text-forensic-300"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
            </div>

            <div>
              <label htmlFor="confirmPassword" className="label">Confirm Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-forensic-500" />
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type={showPassword ? 'text' : 'password'}
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  className="input pl-10"
                  placeholder="••••••••"
                  required
                  autoComplete="new-password"
                  disabled={loading}
                />
              </div>
            </div>

            <button
              type="submit"
              className="btn-primary w-full"
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader2 className="h-5 w-5 animate-spin" />
                  Creating account...
                </>
              ) : (
                'Create account'
              )}
            </button>
          </form>

          <p className="mt-6 text-center text-forensic-400 text-sm">
            Already have an account?{' '}
            <Link to="/login" className="text-accent-blue hover:text-blue-400 font-medium">
              Sign in
            </Link>
          </p>
        </div>

        <p className="mt-6 text-center text-forensic-600 text-sm">
          TraceForge v0.1.0 — Defensive Digital Forensics
        </p>
      </div>
    </div>
  );
}