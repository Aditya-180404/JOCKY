import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { SiteHeader } from '../components/SiteHeader';
import { SiteFooter } from '../components/SiteFooter';
import {
  BookOpen,
  Search,
  ExternalLink,
  Tag,
  Shield,
  Cpu,
  HardDrive,
  Network,
  FileSearch,
  Activity,
  Lock,
  ChevronRight,
} from 'lucide-react';

interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  tags: string[];
  collectors: string[];
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  code: string;
}

const PLAYBOOKS: Playbook[] = [
  {
    id: 'basic_system_triage',
    name: 'Basic System Triage',
    description: 'Collect host OS metadata and running processes in a single verifiable JSON bundle. The ideal starting point for any incident response.',
    category: 'Incident Response',
    tags: ['triage', 'ir', 'beginner'],
    collectors: ['system_info', 'processes'],
    difficulty: 'Beginner',
    code: `investigation "basic_system_triage" {\n    collect system_info\n    collect processes\n    export evidence "system_triage.json"\n}`,
  },
  {
    id: 'full_network_sweep',
    name: 'Full Network Sweep',
    description: 'Enumerate all active TCP/UDP sockets alongside host and process context to pinpoint lateral movement or C2 beaconing.',
    category: 'Network Forensics',
    tags: ['network', 'c2', 'lateral-movement'],
    collectors: ['system_info', 'network_connections', 'processes'],
    difficulty: 'Beginner',
    code: `investigation "full_network_sweep" {\n    collect system_info\n    collect network_connections\n    collect processes { pid name user }\n    export evidence "network_sweep.json"\n}`,
  },
  {
    id: 'process_hash_audit',
    name: 'Process Binary Hash Audit',
    description: 'SHA-256 hash every running binary to catch tampered or injected executables. Essential for malware triage.',
    category: 'Malware Triage',
    tags: ['malware', 'hashing', 'process'],
    collectors: ['processes'],
    difficulty: 'Beginner',
    code: `investigation "process_hash_audit" {\n    collect processes { pid name parent command_line user hash.sha256 }\n    export evidence "process_hashes.json"\n}`,
  },
  {
    id: 'filesystem_integrity',
    name: 'Filesystem Integrity Check',
    description: 'Recursively hash critical directories to detect tampering or rootkit file replacements.',
    category: 'Integrity Monitoring',
    tags: ['filesystem', 'integrity', 'rootkit'],
    collectors: ['files'],
    difficulty: 'Intermediate',
    code: `investigation "filesystem_integrity" {\n    collect files "/etc" { recursive hash.sha256 } limit 200\n    collect files "/usr/bin" { recursive hash.sha256 } limit 500\n    export evidence "fs_integrity.json"\n}`,
  },
  {
    id: 'memory_process_triage',
    name: 'Memory Region Triage',
    description: 'Dump the virtual memory map of a target process to identify injected shellcode, hollowed sections, or heap sprays.',
    category: 'Memory Forensics',
    tags: ['memory', 'injection', 'shellcode'],
    collectors: ['memory_regions', 'processes'],
    difficulty: 'Advanced',
    code: `investigation "memory_process_triage" {\n    metadata { priority = "Critical" }\n    collect processes { pid name hash.sha256 }\n    collect memory_regions pid=1234\n    export evidence "memory_triage.json"\n}`,
  },
  {
    id: 'windows_registry_audit',
    name: 'Windows Registry Audit',
    description: 'Enumerate critical Run keys, Services, and scheduled task entries in the Windows Registry to uncover persistence mechanisms.',
    category: 'Persistence Detection',
    tags: ['registry', 'persistence', 'windows'],
    collectors: ['registry'],
    difficulty: 'Intermediate',
    code: `investigation "windows_registry_audit" {\n    collect registry hive="HKLM" key="SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"\n    collect registry hive="HKLM" key="SYSTEM\\\\CurrentControlSet\\\\Services"\n    export evidence "registry_audit.json"\n}`,
  },
  {
    id: 'artifact_carving',
    name: 'Forensic Artifact Carving',
    description: 'Extract Windows Prefetch, Shimcache, and Event Log artifacts to reconstruct execution history.',
    category: 'Artifact Analysis',
    tags: ['artifacts', 'prefetch', 'shimcache', 'windows'],
    collectors: ['artifacts'],
    difficulty: 'Advanced',
    code: `investigation "artifact_carving" {\n    collect artifacts type="prefetch" path="C:\\\\Windows\\\\Prefetch"\n    collect artifacts type="shimcache"\n    collect artifacts type="eventlog"\n    export evidence "artifact_carving.json"\n}`,
  },
  {
    id: 'log_threat_hunt',
    name: 'Log-Based Threat Hunt',
    description: 'Gather OS event and authentication logs alongside process state to correlate suspicious user activity or privilege escalation.',
    category: 'Threat Hunting',
    tags: ['logs', 'threat-hunt', 'privesc'],
    collectors: ['logs', 'processes', 'system_info'],
    difficulty: 'Intermediate',
    code: `investigation "log_threat_hunt" {\n    metadata { priority = "High" }\n    collect system_info\n    collect logs source="auth"\n    collect logs source="system"\n    collect processes { pid name user parent } where user == "root"\n    export evidence "threat_hunt.json"\n}`,
  },
  {
    id: 'driver_rootkit_hunt',
    name: 'Driver & Rootkit Hunt',
    description: 'Enumerate loaded kernel modules and hash each driver to spot unsigned or injected rootkit drivers.',
    category: 'Rootkit Detection',
    tags: ['drivers', 'rootkit', 'kernel'],
    collectors: ['drivers', 'system_info'],
    difficulty: 'Advanced',
    code: `investigation "driver_rootkit_hunt" {\n    metadata { priority = "Critical" }\n    collect system_info\n    collect drivers\n    export evidence "driver_audit.json"\n}`,
  },
  {
    id: 'full_incident_triage',
    name: 'Full Incident Response Triage',
    description: 'Comprehensive IR sweep covering system, processes, network, filesystem, and logs in a single chainable evidence bundle.',
    category: 'Incident Response',
    tags: ['ir', 'comprehensive', 'triage'],
    collectors: ['system_info', 'processes', 'network_connections', 'files', 'logs'],
    difficulty: 'Intermediate',
    code: `investigation "full_incident_triage" {\n    metadata { author = "DFIR Team" priority = "High" }\n    collect system_info\n    collect processes { pid name parent command_line user hash.sha256 }\n    collect network_connections\n    collect files "/tmp" { recursive hash.sha256 } limit 100\n    collect logs source="auth"\n    export evidence "incident_triage.json"\n}`,
  },
];

const CATEGORIES = ['All', ...Array.from(new Set(PLAYBOOKS.map((p) => p.category))).sort()];

const DIFFICULTY_COLORS: Record<string, string> = {
  Beginner: 'text-emerald-400 bg-emerald-900/30 border-emerald-700/50',
  Intermediate: 'text-amber-400 bg-amber-900/30 border-amber-700/50',
  Advanced: 'text-rose-400 bg-rose-900/30 border-rose-700/50',
};

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  'Incident Response': <Shield className="h-4 w-4" />,
  'Network Forensics': <Network className="h-4 w-4" />,
  'Malware Triage': <Cpu className="h-4 w-4" />,
  'Integrity Monitoring': <HardDrive className="h-4 w-4" />,
  'Memory Forensics': <Activity className="h-4 w-4" />,
  'Persistence Detection': <Lock className="h-4 w-4" />,
  'Artifact Analysis': <FileSearch className="h-4 w-4" />,
  'Threat Hunting': <Search className="h-4 w-4" />,
  'Rootkit Detection': <Shield className="h-4 w-4" />,
};

export function PlaybookGallery() {
  const [query, setQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState('All');
  const [activeDifficulty, setActiveDifficulty] = useState('All');

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return PLAYBOOKS.filter((p) => {
      const matchQuery =
        !q ||
        p.name.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.tags.some((t) => t.includes(q)) ||
        p.collectors.some((c) => c.includes(q));
      const matchCat = activeCategory === 'All' || p.category === activeCategory;
      const matchDiff = activeDifficulty === 'All' || p.difficulty === activeDifficulty;
      return matchQuery && matchCat && matchDiff;
    });
  }, [query, activeCategory, activeDifficulty]);

  return (
    <div className="min-h-screen bg-[#080d15] text-slate-200 font-sans">
      <SiteHeader />

      {/* Hero */}
      <section className="relative border-b border-slate-800/60 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-blue-950/30 via-[#080d15] to-[#080d15]" />
        <div className="relative max-w-6xl mx-auto px-4 sm:px-6 py-10 sm:py-20 text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-950/60 border border-blue-800/40 text-blue-300 text-xs font-semibold mb-6">
            <BookOpen className="h-3.5 w-3.5" />
            Playbook Gallery
          </div>
          <h1 className="text-2xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-white mb-4">
            Forensic Investigation Playbooks
          </h1>
          <p className="text-slate-400 text-sm sm:text-lg max-w-2xl mx-auto">
            Production-ready jocky investigations for incident response, threat hunting, and digital forensics.
            Click any playbook to open it instantly in the Web IDE.
          </p>
        </div>
      </section>

      {/* Filters — sticky below the 56px SiteHeader */}
      <section className="sticky top-14 z-10 border-b border-slate-800/60 bg-[#080d15]/95 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3 flex flex-col sm:flex-row flex-wrap items-start sm:items-center gap-3">
          <div className="relative w-full sm:flex-1 sm:min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search playbooks, collectors, tags…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-600 transition-colors"
            />
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            {CATEGORIES.map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors border ${
                  activeCategory === cat
                    ? 'bg-blue-700 border-blue-600 text-white'
                    : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            {['All', 'Beginner', 'Intermediate', 'Advanced'].map((d) => (
              <button
                key={d}
                onClick={() => setActiveDifficulty(d)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors border ${
                  activeDifficulty === d
                    ? 'bg-blue-700 border-blue-600 text-white'
                    : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-200'
                }`}
              >
                {d}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Grid */}
      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8 sm:py-10">
        {filtered.length === 0 ? (
          <div className="text-center py-24 text-slate-500">
            <BookOpen className="h-12 w-12 mx-auto mb-4 opacity-30" />
            <p className="text-lg">No playbooks match your search.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
            {filtered.map((playbook) => (
              <article
                key={playbook.id}
                className="group flex flex-col bg-[#0d1424] border border-slate-800 rounded-xl p-5 hover:border-blue-700/60 hover:shadow-lg hover:shadow-blue-900/20 transition-all duration-200"
              >
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div className="flex items-center gap-2 text-blue-400">
                    {CATEGORY_ICONS[playbook.category] ?? <Shield className="h-4 w-4" />}
                    <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wide">
                      {playbook.category}
                    </span>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${DIFFICULTY_COLORS[playbook.difficulty]}`}>
                    {playbook.difficulty}
                  </span>
                </div>
                <h2 className="text-base font-bold text-slate-100 mb-2 group-hover:text-blue-300 transition-colors">
                  {playbook.name}
                </h2>
                <p className="text-sm text-slate-400 leading-relaxed flex-1 mb-4">
                  {playbook.description}
                </p>
                <div className="flex flex-wrap gap-1.5 mb-4">
                  {playbook.collectors.map((c) => (
                    <span key={c} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-blue-300 border border-slate-700">
                      {c}
                    </span>
                  ))}
                </div>
                <div className="flex flex-wrap gap-1 mb-5">
                  {playbook.tags.map((t) => (
                    <span key={t} className="flex items-center gap-1 text-[10px] text-slate-500">
                      <Tag className="h-2.5 w-2.5" />
                      {t}
                    </span>
                  ))}
                </div>
                <Link
                  to={`/ide?example=${playbook.id}`}
                  className="mt-auto flex items-center justify-center gap-2 w-full py-2 rounded-lg bg-blue-700/20 border border-blue-700/40 text-blue-300 text-sm font-medium hover:bg-blue-700/40 hover:border-blue-600 transition-colors"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  Open in IDE
                  <ChevronRight className="h-3.5 w-3.5 ml-auto opacity-50 group-hover:opacity-100" />
                </Link>
              </article>
            ))}
          </div>
        )}
      </main>

      <SiteFooter />
    </div>
  );
}
