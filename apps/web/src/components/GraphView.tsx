import React, { useEffect, useRef, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

interface EntityNode {
  entity: {
    display: () => string;
    entity_type: () => string;
  };
  evidence_refs: string[];
  first_seen: string;
  last_seen: string;
  event_count: number;
}

interface Relationship {
  id: string;
  source_entity: any;
  target_entity: any;
  relationship_type: string;
  confidence: number;
  timestamp: string;
  evidence_refs: string[];
}

interface GraphData {
  investigation_id: string;
  host: string;
  entities: Record<string, EntityNode>;
  relationships: Relationship[];
}

interface GraphViewProps {
  data: GraphData | null;
}

// Internal types for force-graph nodes/links
interface FGNode {
  id: string;
  label: string;
  type: string;
  eventCount: number;
  evidenceRefs: string[];
  firstSeen: string;
  lastSeen: string;
  val: number;
  x?: number;
  y?: number;
  __origNode?: EntityNode;
}

interface FGLink {
  source: string | FGNode;
  target: string | FGNode;
  type: string;
  confidence: number;
  timestamp: string;
  evidenceRefs: string[];
  __origLink?: Relationship;
}

export const GraphView: React.FC<GraphViewProps> = ({ data }) => {
  const graphRef = useRef<any>(null);
  const [nodeHover, setNodeHover] = useState<FGNode | null>(null);
  const [linkHover, setLinkHover] = useState<FGLink | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (graphRef.current && data) {
      graphRef.current.d3ReheatSimulation();
    }
  }, [data]);

  if (!data) {
    return (
      <div className="h-[500px] flex items-center justify-center bg-forensic-900 rounded-lg border border-forensic-800">
        <div className="text-center text-forensic-500">
          <div className="text-4xl mb-2">🔍</div>
          <p className="text-lg">No correlation graph data available</p>
          <p className="text-sm mt-1">Run an investigation to generate entity correlations</p>
        </div>
      </div>
    );
  }

  // Convert entities and relationships to force-graph format
  const graphData = {
    nodes: Object.entries(data.entities).map(([key, node]) => ({
      id: key,
      label: node.entity.display(),
      type: node.entity.entity_type(),
      eventCount: node.event_count,
      evidenceRefs: node.evidence_refs,
      firstSeen: node.first_seen,
      lastSeen: node.last_seen,
      val: Math.max(5, Math.min(30, 5 + Math.log(node.event_count + 1) * 5)),
      __origNode: node,
    })),
    links: data.relationships.map((rel) => ({
      source: rel.source_entity.display(),
      target: rel.target_entity.display(),
      type: rel.relationship_type,
      confidence: rel.confidence,
      timestamp: rel.timestamp,
      evidenceRefs: rel.evidence_refs,
      __origLink: rel,
    })),
  };

  // Color mapping for entity types
  const nodeColor = (node: FGNode) => {
    switch (node.type) {
      case 'process':
        return '#38bdf8';
      case 'file':
        return '#fbbf24';
      case 'network_connection':
        return '#a78bfa';
      case 'user':
        return '#4ade80';
      case 'host':
        return '#fb923c';
      case 'driver':
        return '#f87171';
      case 'registry_key':
        return '#34d399';
      case 'memory_region':
        return '#f472b6';
      case 'artifact':
        return '#60a5fa';
      case 'log_event':
        return '#94a3b8';
      default:
        return '#64748b';
    }
  };

  const linkColor = (link: FGLink) => {
    const confidence = link.confidence || 0.5;
    const opacity = Math.max(0.3, confidence);
    return `rgba(148, 163, 184, ${opacity})`;
  };

  const linkWidth = (link: FGLink) => {
    return Math.max(1, (link.confidence || 0.5) * 4);
  };

  // Track mouse position for tooltip
  const handleMouseMove = (e: React.MouseEvent) => {
    setMousePos({ x: e.clientX, y: e.clientY });
  };

  return (
    <div
      className="h-[600px] bg-forensic-950 rounded-lg border border-forensic-800 relative"
      onMouseMove={handleMouseMove}
    >
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        nodeId="id"
        nodeLabel="label"
        nodeVal="val"
        nodeColor={nodeColor}
        nodeCanvasObject={(node: FGNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const scale = globalScale || 1;
          const size = Math.max(node.val / scale, 4);

          // Draw node circle
          ctx.beginPath();
          ctx.arc(0, 0, size, 0, 2 * Math.PI);
          ctx.fillStyle = nodeColor(node);
          ctx.fill();
          ctx.strokeStyle = node === nodeHover ? '#fff' : '#1e293b';
          ctx.lineWidth = node === nodeHover ? 3 / scale : 1.5 / scale;
          ctx.stroke();

          // Draw label
          if (scale > 0.5) {
            ctx.font = `${Math.max(10, 12 / scale)}px monospace`;
            ctx.fillStyle = '#e2e8f0';
            ctx.textAlign = 'center';
            const label = node.label.length > 30 ? node.label.substring(0, 27) + '...' : node.label;
            ctx.fillText(label, 0, -size - 4 / scale);
          }
        }}
        linkColor={linkColor}
        linkWidth={linkWidth}
        linkDirectionalArrowLength={8}
        linkDirectionalArrowColor={linkColor}
        linkDirectionalArrowRelPos={0.5}
        linkCanvasObject={(link: FGLink, ctx: CanvasRenderingContext2D, _globalScale: number) => {
          if (link === linkHover) {
            ctx.strokeStyle = '#fbbf24';
            ctx.lineWidth = 3;
          }
        }}
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.4}
        enableNodeDrag={true}
        enableZoomInteraction={true}
        onNodeHover={(node: FGNode | null) => {
          setNodeHover(node);
          document.body.style.cursor = node ? 'pointer' : 'default';
        }}
        onLinkHover={(link: FGLink | null) => {
          setLinkHover(link);
          document.body.style.cursor = link ? 'pointer' : 'default';
        }}
        onBackgroundClick={() => {
          setNodeHover(null);
          setLinkHover(null);
        }}
      />
      {/* Tooltip */}
      {(nodeHover || linkHover) && (
        <div
          className="fixed z-50 bg-forensic-900 border border-forensic-700 rounded-lg p-3 text-xs font-mono text-forensic-200 pointer-events-none shadow-lg"
          style={{
            left: mousePos.x + 10,
            top: mousePos.y + 10,
          }}
        >
          {nodeHover && (
            <div>
              <div className="font-semibold text-accent-blue mb-1">{nodeHover.label}</div>
              <div className="text-forensic-400">Type: {nodeHover.type}</div>
              <div className="text-forensic-400">Events: {nodeHover.eventCount}</div>
              <div className="text-forensic-400">First seen: {new Date(nodeHover.firstSeen).toLocaleString()}</div>
              <div className="text-forensic-400">Last seen: {new Date(nodeHover.lastSeen).toLocaleString()}</div>
              {nodeHover.evidenceRefs.length > 0 && (
                <div className="mt-1 text-[10px] text-forensic-500">
                  Refs: {nodeHover.evidenceRefs.slice(0, 3).join(', ')}
                  {nodeHover.evidenceRefs.length > 3 && ` +${nodeHover.evidenceRefs.length - 3} more`}
                </div>
              )}
            </div>
          )}
          {linkHover && (
            <div>
              <div className="font-semibold text-accent-purple mb-1">{linkHover.type}</div>
              <div className="text-forensic-400">
                {typeof linkHover.source === 'string' ? linkHover.source : linkHover.source.label} → {typeof linkHover.target === 'string' ? linkHover.target : linkHover.target.label}
              </div>
              <div className="text-forensic-400">Confidence: {(linkHover.confidence * 100).toFixed(0)}%</div>
              <div className="text-forensic-400">
                Time: {new Date(linkHover.timestamp).toLocaleString()}
              </div>
              {linkHover.evidenceRefs.length > 0 && (
                <div className="mt-1 text-[10px] text-forensic-500">
                  Refs: {linkHover.evidenceRefs.slice(0, 3).join(', ')}
                </div>
              )}
            </div>
          )}
        </div>
      )}
      {/* Legend */}
      <div className="absolute bottom-4 right-4 bg-forensic-900/95 border border-forensic-800 rounded-lg p-3 text-xs">
        <div className="font-semibold text-forensic-200 mb-2">Entity Types</div>
        <div className="flex flex-col gap-1">
          {[
            { type: 'process', color: '#38bdf8', label: 'Process' },
            { type: 'file', color: '#fbbf24', label: 'File' },
            { type: 'network_connection', color: '#a78bfa', label: 'Network' },
            { type: 'user', color: '#4ade80', label: 'User' },
            { type: 'host', color: '#fb923c', label: 'Host' },
            { type: 'driver', color: '#f87171', label: 'Driver' },
            { type: 'registry_key', color: '#34d399', label: 'Registry' },
            { type: 'artifact', color: '#60a5fa', label: 'Artifact' },
            { type: 'log_event', color: '#94a3b8', label: 'Log Event' },
          ].map(({ type, color, label }) => (
            <div key={type} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
              <span className="text-forensic-300">{label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};