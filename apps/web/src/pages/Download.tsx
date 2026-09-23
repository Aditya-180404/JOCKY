import { useEffect, useState } from 'react';
import { SiteHeader } from '../components/SiteHeader';
import { SiteFooter } from '../components/SiteFooter';
import { api } from '../services/api';
import {
  Download,
  ShieldCheck,
  Terminal,
  Copy,
  Check,
  AlertCircle,
} from 'lucide-react';

interface PackageInfo {
  platform: string;
  arch: string;
  name: string;
  filename: string;
  version: string;
  size_bytes: number;
  sha256: string;
  release_date: string;
  requirements: string;
  download_url: string;
}

export function DownloadPage() {
  const [packages, setPackages] = useState<PackageInfo[]>([]);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    loadPackages();
  }, []);

  const loadPackages = async () => {
    try {
      const res = await api.get('/api/downloads/info');
      if (res.data && res.data.packages) {
        setPackages(res.data.packages);
      }
    } catch {
      setPackages([]);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const formatSize = (bytes: number) => {
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(2)} MB`;
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 flex flex-col font-sans">
      <SiteHeader />

      <main className="flex-1 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">
        {/* Page Header */}
        <div className="border-b border-slate-800 pb-8 mb-10">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-mono mb-4">
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Official Verifiable Release v0.1.0</span>
          </div>

          <h1 className="text-3xl font-bold font-mono text-white tracking-tight">
            TRACEFORGE Compiler & Toolchain Downloads
          </h1>

          <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
            Download the standalone native TraceForge compiler for offline incident response and forensic triage.
            All binaries are standalone, statically linked, and verified with canonical SHA-256 digests.
          </p>
        </div>

        {/* Available Packages */}
        <div className="space-y-6 mb-12">
          <h2 className="text-lg font-bold text-white font-mono">Available Release Packages</h2>

          {packages.length === 0 ? (
            <div className="p-5 rounded border border-slate-800 bg-[#0e1422] text-sm text-slate-400">
              No downloadable artifacts are currently published by the API. Build the standalone compiler from source
              or check back when a release package is available.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              {packages.map((pkg) => (
              <div
                key={pkg.filename}
                className="p-5 rounded border border-slate-800 bg-[#0e1422] flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="font-mono text-xs text-blue-400 font-semibold px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20">
                      {pkg.platform} {pkg.arch}
                    </span>
                    <span className="font-mono text-xs text-slate-400">{formatSize(pkg.size_bytes)}</span>
                  </div>

                  <h3 className="text-base font-bold text-white mb-1">{pkg.name}</h3>
                  <p className="text-xs text-slate-400 mb-4">{pkg.requirements}</p>

                  <div className="p-2.5 rounded bg-[#090d15] border border-slate-800/80 mb-4 font-mono text-[11px]">
                    <div className="text-slate-400 mb-1 flex items-center justify-between">
                      <span>SHA-256 Digest:</span>
                      <button
                        onClick={() => handleCopyHash(pkg.sha256)}
                        className="text-slate-400 hover:text-slate-200 inline-flex items-center gap-1"
                      >
                        {copiedHash === pkg.sha256 ? (
                          <Check className="h-3 w-3 text-emerald-400" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        <span>{copiedHash === pkg.sha256 ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <div className="text-slate-300 break-all">{pkg.sha256}</div>
                  </div>
                </div>

                <a
                  href={pkg.download_url}
                  download={pkg.filename}
                  className="w-full inline-flex items-center justify-center gap-2 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs transition-colors"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Download {pkg.filename}</span>
                </a>
              </div>
              ))}
            </div>
          )}
        </div>

        {/* Linux Target Status */}
        <div className="p-5 rounded border border-slate-800 bg-[#0e1422] mb-12">
          <div className="flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-bold text-white font-mono mb-1">
                Linux x86_64 & ARM64 Binaries
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                No Linux package is currently published by the downloads API. On Linux systems, TraceForge can be
                built directly from source:
              </p>
              <pre className="mt-3 p-3 rounded bg-[#090d15] border border-slate-800 font-mono text-xs text-slate-300">
{`# Clone and build native release binary on Linux
git clone https://github.com/Aditya-180404/TRACEFORGE.git
cd TRACEFORGE
cargo build --release -p traceforge-cli
./target/release/traceforge --version`}
              </pre>
            </div>
          </div>
        </div>

        {/* Quick Verification Guide */}
        <div className="p-5 rounded border border-slate-800 bg-[#0e1422]">
          <h3 className="text-sm font-bold text-white font-mono mb-2 flex items-center gap-2">
            <Terminal className="h-4 w-4 text-blue-400" />
            <span>Verifying Download Authenticity</span>
          </h3>
          <p className="text-xs text-slate-400 mb-3">
            Verify the downloaded archive in PowerShell using the native Get-FileHash utility:
          </p>
          <pre className="p-3 rounded bg-[#090d15] border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto">
{`# Compute SHA-256 hash in PowerShell
Get-FileHash .\\TRACEFORGE-0.1.0-windows-x64.zip -Algorithm SHA256

# Verify that the output matches:
# 35B29F54B6879B039B462A97293F3B7ED6ECDF25A4A2B90A7C55D65EB2BD7247`}
          </pre>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
