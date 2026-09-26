import { useState } from 'react';
import { SiteHeader } from '../components/SiteHeader';
import { SiteFooter } from '../components/SiteFooter';
import { Link } from 'react-router-dom';
import {
  Code2,
  Play,
  Copy,
  Check,
  Download,
} from 'lucide-react';

const EXAMPLES = [
  {
    title: 'Basic System Triage',
    category: 'Triage',
    description: 'Quick initial incident assessment collecting host architecture, OS info, and process list.',
    code: `investigation "basic_system_triage" {
    collect system_info

    collect processes

    export evidence "system_triage.json"
}`,
  },
  {
    title: 'Process Investigation & Hashes',
    category: 'Process Forensics',
    description: 'Extract running processes with PID, parent PID, command lines, users, and SHA-256 binary digests.',
    code: `investigation "process_investigation" {
    collect processes {
        pid
        name
        parent
        command_line
        user
        hash.sha256
    }

    export evidence "process_evidence.json"
}`,
  },
  {
    title: 'Suspicious Network Endpoints',
    category: 'Network Forensics',
    description: 'Enumerate open listening sockets, ports, and protocols to identify persistence or unauthorized listeners.',
    code: `investigation "network_investigation" {
    collect system_info

    collect network_connections

    export evidence "network_evidence.json"
}`,
  },
  {
    title: 'Privileged User Activity Audit',
    category: 'User Auditing',
    description: 'Filter system process execution specifically for root or elevated user accounts.',
    code: `investigation "user_investigation" {
    collect system_info

    collect processes {
        pid
        name
        user
    } where user == "root"

    export evidence "user_evidence.json"
}`,
  },
  {
    title: 'Filesystem Integrity & Hashing',
    category: 'Filesystem',
    description: 'Scan configuration directories recursively, generating SHA-256 checksums up to a defined limit.',
    code: `investigation "filesystem_investigation" {
    collect system_info

    collect files "/etc" {
        recursive
        hash.sha256
    } limit 50

    export evidence "filesystem_evidence.json"
}`,
  },
  {
    title: 'Evidence Hashing & Process Triage',
    category: 'Integrity',
    description: 'Calculates SHA-256 cryptographic hashes for executable binaries of all running tasks.',
    code: `investigation "evidence_hashing" {
    collect processes {
        pid
        name
        hash.sha256
    }

    export evidence "hashed_evidence.json"
}`,
  },
  {
    title: 'Complete Multi-Collector Triage',
    category: 'Incident Response',
    description: 'Comprehensive investigation script aggregating system, processes, network, and case metadata.',
    code: `investigation "complete_basic_triage" {
    metadata {
        author = "Forensic Analyst"
        priority = "High"
        category = "Incident Response"
    }

    collect system_info

    collect processes {
        pid
        name
        parent
        command_line
        user
        hash.sha256
    }

    collect network_connections

    export evidence "complete_triage_evidence.json"
}`,
  },
];

export function ExamplesPage() {
  const [filter, setFilter] = useState('All');
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const categories = ['All', 'Triage', 'Process Forensics', 'Network Forensics', 'User Auditing', 'Filesystem', 'Incident Response'];

  const filteredExamples =
    filter === 'All' ? EXAMPLES : EXAMPLES.filter((ex) => ex.category === filter);

  const handleCopy = (code: string, index: number) => {
    navigator.clipboard.writeText(code);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleDownload = (code: string, title: string) => {
    const filename = `${title.toLowerCase().replace(/[^a-z0-9]/g, '_')}.jy`;
    const blob = new Blob([code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 flex flex-col font-sans">
      <SiteHeader />

      <main className="flex-1 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">
        {/* Page Title */}
        <div className="border-b border-slate-800 pb-8 mb-8 text-center max-w-2xl mx-auto">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-mono mb-3">
            <Code2 className="h-3.5 w-3.5" />
            <span>Canonical Investigation Scripts</span>
          </div>
          <h1 className="text-3xl font-bold font-mono text-white">
            jockey Examples
          </h1>
          <p className="mt-2 text-xs text-slate-400">
            Explore ready-to-run forensic investigations. Open any example in the Web IDE or download the `.jy` source.
          </p>
        </div>

        {/* Category Filter Pills */}
        <div className="flex flex-wrap items-center justify-center gap-1.5 mb-8">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                filter === cat
                  ? 'bg-blue-600 text-white font-medium'
                  : 'bg-[#0e1422] border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Examples Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {filteredExamples.map((ex, index) => (
            <div
              key={ex.title}
              className="bg-[#0e1422] border border-slate-800 rounded flex flex-col justify-between"
            >
              <div className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono text-blue-400 bg-blue-950/60 px-2 py-0.5 rounded border border-blue-800/40">
                    {ex.category}
                  </span>
                </div>
                <h3 className="text-sm font-bold font-mono text-white">{ex.title}</h3>
                <p className="mt-1 text-xs text-slate-400">{ex.description}</p>

                {/* Code Box */}
                <div className="mt-3 p-3.5 rounded bg-[#090d15] border border-slate-800 font-mono text-xs text-slate-200 overflow-x-auto max-h-48">
                  <pre>{ex.code}</pre>
                </div>
              </div>

              {/* Action Toolbar */}
              <div className="px-5 py-2.5 bg-[#090d15] border-t border-slate-800 flex items-center justify-between text-xs">
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => handleCopy(ex.code, index)}
                    className="flex items-center gap-1 text-slate-400 hover:text-slate-200"
                  >
                    {copiedIndex === index ? (
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                    <span>{copiedIndex === index ? 'Copied' : 'Copy'}</span>
                  </button>

                  <button
                    onClick={() => handleDownload(ex.code, ex.title)}
                    className="flex items-center gap-1 text-slate-400 hover:text-slate-200"
                  >
                    <Download className="h-3.5 w-3.5" />
                    <span>Download</span>
                  </button>
                </div>

                <Link
                  to={`/ide?example=${encodeURIComponent(ex.code.match(/investigation\s+"([^"]+)"/)?.[1] || '')}`}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white font-medium transition-colors"
                >
                  <Play className="h-3 w-3 fill-current" />
                  <span>Open in Web IDE</span>
                </Link>
              </div>
            </div>
          ))}
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
