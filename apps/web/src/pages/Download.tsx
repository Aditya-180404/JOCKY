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
  Monitor,
  Package,
  Zap,
  ExternalLink,
  ChevronRight,
  Globe,
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

type PlatformTab = 'linux' | 'windows' | 'debian';

const GITHUB_REPO = 'Aditya-180404/JOCKY';
const RAW_BASE = `https://raw.githubusercontent.com/${GITHUB_REPO}/main/scripts`;
const RELEASES_URL = `https://github.com/${GITHUB_REPO}/releases/latest`;

export function DownloadPage() {
  const [packages, setPackages] = useState<PackageInfo[]>([]);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<PlatformTab>('linux');

  useEffect(() => {
    // Auto-detect platform
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('win')) setActiveTab('windows');
    else setActiveTab('linux');

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

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
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
        'application/gzip',
        'application/x-gzip',
        'application/octet-stream',
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

  // ── Code snippet component ────────────────────────────────────────────────
  const CodeBlock = ({ code, id, lang = 'bash' }: { code: string; id: string; lang?: string }) => (
    <div className="relative group mt-3">
      <div className="flex items-center justify-between px-3 py-1.5 rounded-t bg-[#060a12] border border-slate-800 border-b-0">
        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">{lang}</span>
        <button
          onClick={() => handleCopy(code, id)}
          className="inline-flex items-center gap-1 text-slate-500 hover:text-slate-200 transition-colors text-[11px]"
        >
          {copiedId === id ? (
            <><Check className="h-3 w-3 text-emerald-400" /><span className="text-emerald-400">Copied!</span></>
          ) : (
            <><Copy className="h-3 w-3" /><span>Copy</span></>
          )}
        </button>
      </div>
      <pre className="p-4 rounded-b bg-[#060a12] border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed whitespace-pre-wrap">
        {code}
      </pre>
    </div>
  );

  // ── Platform tab content ───────────────────────────────────────────────────
  const LinuxContent = () => (
    <div className="space-y-6">
      <div className="p-5 rounded-lg border border-emerald-500/20 bg-emerald-500/5">
        <div className="flex items-center gap-2 mb-1">
          <Zap className="h-4 w-4 text-emerald-400" />
          <span className="text-sm font-bold text-emerald-300">One-liner Install (Recommended)</span>
        </div>
        <p className="text-xs text-slate-400 mb-0">
          Downloads the latest release binary, installs to <code className="bg-[#090d15] px-1 rounded">/usr/local/bin</code>, and configures your PATH automatically.
        </p>
        <CodeBlock
          id="linux-oneliner"
          code={`curl -fsSL ${RAW_BASE}/install.sh | bash`}
        />
      </div>

      <div className="p-5 rounded-lg border border-slate-700/50 bg-[#0e1422]">
        <h4 className="text-xs font-bold text-white mb-3 font-mono uppercase tracking-wider">Install Options</h4>
        <CodeBlock
          id="linux-opts"
          code={`# Install specific version
curl -fsSL ${RAW_BASE}/install.sh | bash -s -- --version v0.1.0

# Install to custom location (no sudo required)
curl -fsSL ${RAW_BASE}/install.sh | bash -s -- --prefix ~/.local

# Uninstall
curl -fsSL ${RAW_BASE}/install.sh | bash -s -- --uninstall`}
        />
      </div>

      <div className="p-5 rounded-lg border border-slate-700/50 bg-[#0e1422]">
        <h4 className="text-xs font-bold text-white mb-3 font-mono uppercase tracking-wider">Build from Source</h4>
        <CodeBlock
          id="linux-source"
          code={`# Prerequisites: Rust (rustup.rs) + LLVM 21
git clone https://github.com/${GITHUB_REPO}.git
cd JOCKY
python3 scripts/setup-llvm-linux.py
cargo build --release -p jocky-compiler-cli
sudo cp target/release/jocky /usr/local/bin/
jocky --version`}
        />
        <p className="mt-3 text-xs text-slate-500">
          For ARM64: <code className="bg-[#090d15] px-1 rounded">rustup target add aarch64-unknown-linux-gnu</code> then build with <code className="bg-[#090d15] px-1 rounded">--target aarch64-unknown-linux-gnu</code>
        </p>
      </div>

      <div className="p-5 rounded-lg border border-slate-700/50 bg-[#0e1422]">
        <h4 className="text-xs font-bold text-white mb-3 font-mono uppercase tracking-wider">After Installation</h4>
        <CodeBlock
          id="linux-after"
          code={`jocky --version           # verify install
jocky --help              # show all commands
jocky check script.jy     # validate a .jy file
jocky script.jy           # compile to native binary`}
        />
      </div>
    </div>
  );

  const WindowsContent = () => (
    <div className="space-y-6">
      <div className="p-5 rounded-lg border border-emerald-500/20 bg-emerald-500/5">
        <div className="flex items-center gap-2 mb-1">
          <Zap className="h-4 w-4 text-emerald-400" />
          <span className="text-sm font-bold text-emerald-300">One-liner Install — PowerShell (Run as Administrator)</span>
        </div>
        <p className="text-xs text-slate-400 mb-0">
          Downloads the latest <code className="bg-[#090d15] px-1 rounded">.zip</code>, extracts <code className="bg-[#090d15] px-1 rounded">jocky.exe</code>, adds to system PATH, and creates a firewall rule — all automatically.
        </p>
        <CodeBlock
          id="win-oneliner"
          lang="powershell"
          code={`irm ${RAW_BASE}/install.ps1 | iex`}
        />
      </div>

      <div className="p-5 rounded-lg border border-slate-700/50 bg-[#0e1422]">
        <h4 className="text-xs font-bold text-white mb-3 font-mono uppercase tracking-wider">PowerShell Options</h4>
        <CodeBlock
          id="win-opts"
          lang="powershell"
          code={`# Install specific version
& ([scriptblock]::Create((irm ${RAW_BASE}/install.ps1))) -Version v0.1.0

# Install to custom directory
& ([scriptblock]::Create((irm ${RAW_BASE}/install.ps1))) -InstallDir "C:\\Tools\\jocky"

# Skip firewall rule
& ([scriptblock]::Create((irm ${RAW_BASE}/install.ps1))) -NoFirewall

# Uninstall
& ([scriptblock]::Create((irm ${RAW_BASE}/install.ps1))) -Uninstall`}
        />
      </div>

      <div className="p-5 rounded-lg border border-slate-700/50 bg-[#0e1422]">
        <h4 className="text-xs font-bold text-white mb-3 font-mono uppercase tracking-wider">Manual ZIP Install</h4>
        <p className="text-xs text-slate-400 mb-3">
          Download the ZIP from Releases, extract it, and run the bundled installer:
        </p>
        <CodeBlock
          id="win-manual"
          lang="powershell"
          code={`# Step 1: Download ZIP
Invoke-WebRequest -Uri "https://github.com/${GITHUB_REPO}/releases/latest/download/jocky_0.1.0_windows_x86_64.zip" \`
  -OutFile jocky.zip

# Step 2: Extract
Expand-Archive -Path jocky.zip -DestinationPath .\\jocky-setup

# Step 3: Run bundled installer (as Administrator)
cd jocky-setup
powershell -ExecutionPolicy Bypass -File install.ps1

# Step 4: Verify
jocky --version`}
        />
      </div>

      <div className="p-5 rounded-lg border border-slate-700/50 bg-[#0e1422]">
        <h4 className="text-xs font-bold text-white mb-3 font-mono uppercase tracking-wider">Verify SHA-256</h4>
        <CodeBlock
          id="win-sha"
          lang="powershell"
          code={`# Compute hash
Get-FileHash .\\jocky_0.1.0_windows_x86_64.zip -Algorithm SHA256

# Compare with the published SHA-256 from the release page above`}
        />
      </div>
    </div>
  );

  const DebianContent = () => (
    <div className="space-y-6">
      <div className="p-5 rounded-lg border border-emerald-500/20 bg-emerald-500/5">
        <div className="flex items-center gap-2 mb-1">
          <Zap className="h-4 w-4 text-emerald-400" />
          <span className="text-sm font-bold text-emerald-300">Install .deb Package (Recommended)</span>
        </div>
        <p className="text-xs text-slate-400 mb-0">
          Integrates with apt — installs <code className="bg-[#090d15] px-1 rounded">jocky</code> to <code className="bg-[#090d15] px-1 rounded">/usr/bin</code> and registers it as a system package.
        </p>
        <CodeBlock
          id="deb-install"
          code={`# Download latest .deb
curl -fsSL https://api.github.com/repos/${GITHUB_REPO}/releases/latest \\
  | grep "browser_download_url.*\\.deb\\"" \\
  | cut -d '"' -f 4 \\
  | xargs -I {} curl -fsSL {} -o jocky.deb

# Install
sudo dpkg -i jocky.deb

# Or fix dependencies if needed
sudo apt-get install -f

jocky --version`}
        />
      </div>

      <div className="p-5 rounded-lg border border-slate-700/50 bg-[#0e1422]">
        <h4 className="text-xs font-bold text-white mb-3 font-mono uppercase tracking-wider">Specific Version</h4>
        <CodeBlock
          id="deb-specific"
          code={`# Download a specific version
curl -fsSL https://github.com/${GITHUB_REPO}/releases/download/v0.1.0/jocky_0.1.0_amd64.deb -o jocky.deb
sudo dpkg -i jocky.deb`}
        />
      </div>

      <div className="p-5 rounded-lg border border-slate-700/50 bg-[#0e1422]">
        <h4 className="text-xs font-bold text-white mb-3 font-mono uppercase tracking-wider">Uninstall</h4>
        <CodeBlock
          id="deb-uninstall"
          code={`sudo dpkg -r jocky        # remove binary, keep config
sudo dpkg -P jocky        # purge completely`}
        />
      </div>
    </div>
  );

  const TABS: { id: PlatformTab; label: string; icon: React.ReactNode }[] = [
    { id: 'linux',   label: 'Linux',   icon: <Terminal className="h-3.5 w-3.5" /> },
    { id: 'windows', label: 'Windows', icon: <Monitor className="h-3.5 w-3.5" /> },
    { id: 'debian',  label: 'Debian / Ubuntu', icon: <Package className="h-3.5 w-3.5" /> },
  ];

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 flex flex-col font-sans">
      <SiteHeader />

      <main className="flex-1 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">

        {/* ── Page Header ── */}
        <div className="border-b border-slate-800 pb-8 mb-10">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-mono mb-4">
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Official Verifiable Release v0.1.0</span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-bold font-mono text-white tracking-tight">
            JOCKY Compiler &amp; Toolchain Downloads
          </h1>

          <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
            Download the standalone native JOCKY compiler for offline incident response and forensic triage.
            All binaries are standalone, statically linked, and verified with canonical SHA-256 digests.
          </p>

          <a
            href={RELEASES_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-4 inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            <Globe className="h-3.5 w-3.5" />
            View all releases on GitHub
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>

        {/* ── Alerts ── */}
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

        {/* ── Quick Install — Platform Tabs ── */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-white font-mono mb-1">⚡ Quick Install</h2>
          <p className="text-xs text-slate-400 mb-5">
            One command — downloads the binary, installs globally, and configures your PATH. No Rust or LLVM required.
          </p>

          {/* Tab bar */}
          <div className="flex gap-1 mb-6 p-1 rounded-lg bg-[#0e1422] border border-slate-800 overflow-x-auto w-full sm:w-fit">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                id={`tab-${tab.id}`}
                onClick={() => setActiveTab(tab.id)}
                className={`
                  inline-flex items-center gap-1.5 px-4 py-2 rounded-md text-xs font-medium transition-all
                  ${activeTab === tab.id
                    ? 'bg-blue-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'}
                `}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="min-h-0">
            {activeTab === 'linux'   && <LinuxContent />}
            {activeTab === 'windows' && <WindowsContent />}
            {activeTab === 'debian'  && <DebianContent />}
          </div>
        </section>

        {/* ── Available API Packages ── */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-white font-mono mb-1">Available Release Packages</h2>
          <p className="text-xs text-slate-400 mb-5">
            Pre-built binaries served directly from this server — SHA-256 verified on download.
          </p>

          {packages.length === 0 ? (
            <div className="p-5 rounded border border-slate-800 bg-[#0e1422]">
              <div className="flex items-start gap-3">
                <Info className="h-5 w-5 text-slate-500 shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm text-slate-300 font-medium mb-1">No server packages published yet</p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Binaries are not yet published via this API. Use the one-liner installers above to download from GitHub Releases,
                    or build from source.
                  </p>
                  <a
                    href={RELEASES_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mt-3 inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    Browse GitHub Releases <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              </div>
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
                          onClick={() => handleCopy(pkg.sha256, `hash-${pkg.filename}`)}
                          className="text-slate-400 hover:text-slate-200 inline-flex items-center gap-1"
                        >
                          {copiedId === `hash-${pkg.filename}` ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                          <span>{copiedId === `hash-${pkg.filename}` ? 'Copied' : 'Copy'}</span>
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
        </section>

        {/* ── Verification Guide ── */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-white font-mono mb-1">Verifying Download Integrity</h2>
          <p className="text-xs text-slate-400 mb-5">
            All releases include <code className="bg-[#090d15] px-1 rounded">.sha256</code> checksum files. Verify before running.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="p-5 rounded border border-slate-800 bg-[#0e1422]">
              <div className="flex items-center gap-2 mb-3">
                <Terminal className="h-4 w-4 text-blue-400" />
                <h3 className="text-sm font-bold text-white font-mono">Linux</h3>
              </div>
              <div className="relative mt-0">
                <pre className="p-4 rounded bg-[#060a12] border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
{`# Verify SHA-256
sha256sum jocky_0.1.0_linux_x86_64.tar.gz
# Output should match the .sha256 file

# Or automatically:
sha256sum -c jocky_0.1.0_linux_x86_64.tar.gz.sha256`}
                </pre>
              </div>
            </div>

            <div className="p-5 rounded border border-slate-800 bg-[#0e1422]">
              <div className="flex items-center gap-2 mb-3">
                <Monitor className="h-4 w-4 text-blue-400" />
                <h3 className="text-sm font-bold text-white font-mono">Windows PowerShell</h3>
              </div>
              <div className="relative mt-0">
                <pre className="p-4 rounded bg-[#060a12] border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
{`# Compute SHA-256
Get-FileHash .\\jocky_0.1.0_windows_x86_64.zip -Algorithm SHA256

# Compare with the published hash above
# Both should match exactly`}
                </pre>
              </div>
            </div>
          </div>
        </section>

        {/* ── GitHub Releases link ── */}
        <div className="p-5 rounded-lg border border-blue-500/20 bg-blue-500/5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <p className="text-sm font-bold text-white mb-0.5">All versions &amp; release notes</p>
            <p className="text-xs text-slate-400">Find older releases, changelogs, and source code archives on GitHub.</p>
          </div>
          <a
            href={RELEASES_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-4 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium transition-colors whitespace-nowrap flex-shrink-0"
          >
            GitHub Releases
            <ChevronRight className="h-3.5 w-3.5" />
          </a>
        </div>

      </main>

      <SiteFooter />
    </div>
  );
}
