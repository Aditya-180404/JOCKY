import { useEffect, useState, useCallback } from 'react';
import { SiteHeader } from '../components/SiteHeader';
import { SiteFooter } from '../components/SiteFooter';
import { api } from '../services/api';
import {
  Download,
  ShieldCheck,
  Terminal,
  Copy,
  Check,
  Info,
  Loader2,
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
  content_type: string;
  release_date: string;
  requirements: string;
  download_url: string;
}

export function DownloadPage() {
  const [packages, setPackages] = useState<PackageInfo[]>([]);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

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

  const handleDownload = useCallback(async (pkg: PackageInfo) => {
    setDownloading(pkg.filename);
    setDownloadError(null);
    setDownloadSuccess(null);
    try {
      const response = await api.get<Blob>(pkg.download_url, {
        responseType: 'blob',
        params: { sha256: pkg.sha256 },
      });
      const expectedContentType = pkg.content_type.toLowerCase();
      if (![
        'application/zip',
        'application/vnd.debian.binary-package',
        'application/vnd.microsoft.portable-executable',
      ].includes(expectedContentType)) {
        throw new Error('The package metadata has an unsupported MIME type');
      }
      const contentType = String(response.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      if (contentType !== expectedContentType) {
        throw new Error(`Unexpected download type: ${contentType || 'missing Content-Type'}`);
      }
      const disposition = String(response.headers['content-disposition'] || '');
      const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
      if (!/attachment/i.test(disposition) || filenameMatch?.[1] !== pkg.filename) {
        throw new Error('The server returned an unexpected download filename');
      }

      const blob = response.data;
      const contentLength = Number(response.headers['content-length'] || 0);
      if (blob.size === 0 || (contentLength > 0 && blob.size !== contentLength)) {
        throw new Error('The downloaded package is empty or incomplete');
      }

      const hashBuffer = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
      const actualHash = Array.from(new Uint8Array(hashBuffer), (byte) => byte.toString(16).padStart(2, '0')).join('');
      if (!/^[a-f0-9]{64}$/i.test(pkg.sha256) || actualHash !== pkg.sha256.toLowerCase()) {
        throw new Error('The downloaded package SHA-256 does not match the published metadata');
      }

      const url = URL.createObjectURL(new Blob([blob], { type: expectedContentType }));
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = pkg.filename;
      anchor.style.display = 'none';
      document.body.appendChild(anchor);
      anchor.click();

      setTimeout(() => {
        document.body.removeChild(anchor);
        URL.revokeObjectURL(url);
      }, 100);
      setDownloadSuccess(`Downloaded and verified ${pkg.filename}`);
    } catch (err) {
      setDownloadError(
        err instanceof Error ? err.message : 'Download failed. Try right-clicking and using "Save link as..."'
      );
    } finally {
      setDownloading(null);
    }
  }, []);

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
            JOCKEY Compiler &amp; Toolchain Downloads
          </h1>

          <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
            Download the standalone native JOCKEY compiler for offline incident response and forensic triage.
            All binaries are standalone, statically linked, and verified with canonical SHA-256 digests.
          </p>
        </div>

        {/* Download Error */}
        {downloadError && (
          <div className="mb-6 p-4 rounded border border-red-500/30 bg-red-500/10 flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm text-red-300 font-medium">Download Error</p>
              <p className="text-xs text-red-400 mt-1">{downloadError}</p>
            </div>
          </div>
        )}
        {downloadSuccess && (
          <div role="status" className="mb-6 p-4 rounded border border-emerald-500/30 bg-emerald-500/10 text-sm text-emerald-300">
            {downloadSuccess}
          </div>
        )}

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
                  <p className="text-xs text-slate-400 mb-1">
                    <span className="font-mono text-slate-300">{pkg.filename}</span>
                  </p>
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

                <button
                  onClick={() => handleDownload(pkg)}
                  disabled={downloading === pkg.filename}
                  className="w-full inline-flex items-center justify-center gap-2 py-2.5 rounded bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-wait text-white font-medium text-xs transition-colors"
                >
                  {downloading === pkg.filename ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>Downloading {pkg.filename}...</span>
                    </>
                  ) : (
                    <>
                      <Download className="h-3.5 w-3.5" />
                      <span>Download {pkg.filename}</span>
                    </>
                  )}
                </button>
              </div>
              ))}
            </div>
          )}
        </div>

        {/* Linux Target Status */}
        <div className="p-5 rounded border border-slate-800 bg-[#0e1422] mb-12">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-blue-400 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-bold text-white font-mono mb-1">
                Linux x86_64 &amp; ARM64 Binaries
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Linux binaries are built from source for optimal compatibility with the target system's libc and kernel.
                Build the native release binary on your Linux host:
              </p>
              <pre className="mt-3 p-3 rounded bg-[#090d15] border border-slate-800 font-mono text-xs text-slate-300">
{`# Clone and build native release binary on Linux
git clone https://github.com/Aditya-180404/jockey.git
cd jockey
cargo build --release -p jockey-cli
./target/release/jockey --version`}
              </pre>
              <p className="mt-3 text-xs text-slate-400">
                For cross-compilation to Linux ARM64, install the target and use: <br />
                <code className="font-mono bg-[#090d15] px-1 rounded">rustup target add aarch64-unknown-linux-gnu</code> then <code className="font-mono bg-[#090d15] px-1 rounded">cargo build --release --target aarch64-unknown-linux-gnu -p jockey-cli</code>
              </p>
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
Get-FileHash .\\jockey_0.1.0_windows_amd64.zip -Algorithm SHA256

# Verify that the output matches the published SHA-256 from the download page`}
          </pre>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
