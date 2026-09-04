import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'motion/react';
import { Card, CardContent } from '@/components/ui/card';
import { Network, Server, User, Mail, Link as LinkIcon, Shield, Globe, RefreshCw, AlertTriangle, ZoomIn, ZoomOut, Maximize2, Layers } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useLanguage } from '@/contexts/LanguageContext';

export interface GraphNode {
  id: string;
  type: 'domain' | 'email' | 'user' | 'attacker' | 'malware' | 'INTERNAL_SOURCE' | 'INFRASTRUCTURE' | 'DECEPTIVE_DOMAIN' | 'IDENTITY' | 'EXFILTRATION_MAILBOX' | 'CREDENTIAL_HARVESTER' | 'VICTIM_GATEWAY' | 'TARGET';
  label: string;
  x: number;
  y: number;
  details?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  type?: string;
  relationship?: string;
}

const defaultNodes: GraphNode[] = [
  { id: 'n1', type: 'attacker', label: '185.220.101.45 (Attacker MTA)', x: 10, y: 50, details: 'Sending mail gateway exhibiting SPF/DMARC failure' },
  { id: 'n2', type: 'domain', label: 'm1crosoft-support.com', x: 28, y: 25, details: 'Typosquatted domain with homoglyph numeral 1' },
  { id: 'n3', type: 'domain', label: 'microsoft-security-verification.example.com', x: 28, y: 75, details: 'Credential harvester landing host' },
  { id: 'n4', type: 'email', label: 'security@m1crosoft-support.com', x: 52, y: 25, details: 'Forged header sender claiming Microsoft Security' },
  { id: 'n5', type: 'email', label: 'microsoft.verify.account@gmail.com', x: 52, y: 75, details: 'Exfiltration reply-to mailbox' },
  { id: 'n6', type: 'user', label: 'mx.company.com (Gateway)', x: 74, y: 50, details: 'Target enterprise perimeter boundary MX' },
  { id: 'n7', type: 'user', label: 'employee@company.com (Target)', x: 92, y: 50, details: 'Intended phishing recipient' },
];

const defaultEdges: GraphEdge[] = [
  { source: 'n1', target: 'n6', relationship: 'TRANSMITS_SMTP', type: 'sent' },
  { source: 'n2', target: 'n4', relationship: 'AUTHORIZES', type: 'hosted' },
  { source: 'n4', target: 'n5', relationship: 'DIVERTS_REPLY', type: 'payload' },
  { source: 'n4', target: 'n3', relationship: 'DISTRIBUTES_LINK', type: 'phished' },
  { source: 'n6', target: 'n7', relationship: 'DELIVERS_TO', type: 'sent' },
];

export function AttackGraph() {
  const { t } = useLanguage();
  const [nodes, setNodes] = useState<GraphNode[]>(defaultNodes);
  const [edges, setEdges] = useState<GraphEdge[]>(defaultEdges);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(defaultNodes[0]);
  const [sourceMode, setSourceMode] = useState<'sample' | 'live_forensics'>('sample');
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const canvasRef = useRef<HTMLDivElement>(null);

  // Helper to normalize node coordinates safely to 5% - 95% range
  const normalizeNodes = (rawNodes: GraphNode[]): GraphNode[] => {
    if (!rawNodes || rawNodes.length === 0) return [];
    
    // Check if any coordinates are large pixel values (> 100)
    const maxX = Math.max(...rawNodes.map(n => n.x || 0), 1);
    const maxY = Math.max(...rawNodes.map(n => n.y || 0), 1);
    const isPixelScale = maxX > 100 || maxY > 100;

    return rawNodes.map((node, index) => {
      let x = node.x;
      let y = node.y;

      if (isPixelScale) {
        // Map pixel coordinates down to 8% - 92%
        x = 8 + ((node.x / maxX) * 84);
        y = 15 + ((node.y / maxY) * 70);
      } else {
        // If they were already percentages, clamp them so they never go offscreen
        x = Math.max(8, Math.min(92, x));
        y = Math.max(12, Math.min(88, y));
      }

      // If all nodes have identical coordinates, space them in an auto-layout grid
      if (rawNodes.filter(n => n.x === node.x && n.y === node.y).length > 1) {
        x = 10 + (index * (80 / Math.max(rawNodes.length - 1, 1)));
        y = index % 2 === 0 ? 30 : 65;
      }

      return {
        ...node,
        x: Math.round(x * 10) / 10,
        y: Math.round(y * 10) / 10
      };
    });
  };

  const loadActiveGraph = () => {
    try {
      const storedGraph = localStorage.getItem('neuroshield_active_attack_graph');
      if (storedGraph) {
        const parsed = JSON.parse(storedGraph);
        if (parsed.nodes && parsed.nodes.length > 0) {
          const normalized = normalizeNodes(parsed.nodes);
          setNodes(normalized);
          setEdges(parsed.edges || []);
          setSourceMode('live_forensics');
          setSelectedNode(normalized[0] || null);
          return;
        }
      }
    } catch {
      // ignore parsing errors
    }
  };

  useEffect(() => {
    loadActiveGraph();

    const handleStorage = () => {
      loadActiveGraph();
    };

    window.addEventListener('storage', handleStorage);
    return () => {
      window.removeEventListener('storage', handleStorage);
    };
  }, []);

  const resetToSample = () => {
    setNodes(defaultNodes);
    setEdges(defaultEdges);
    setSourceMode('sample');
    setSelectedNode(defaultNodes[0]);
    setZoomLevel(1);
  };

  const getNodeIcon = (type: GraphNode['type']) => {
    switch (type) {
      case 'attacker':
      case 'INFRASTRUCTURE':
      case 'INTERNAL_SOURCE':
        return <Server className="w-4 h-4 sm:w-5 sm:h-5 text-cyber-red" />;
      case 'domain':
      case 'DECEPTIVE_DOMAIN':
      case 'CREDENTIAL_HARVESTER':
        return <LinkIcon className="w-4 h-4 sm:w-5 sm:h-5 text-[#f59e0b]" />;
      case 'email':
      case 'IDENTITY':
      case 'EXFILTRATION_MAILBOX':
        return <Mail className="w-4 h-4 sm:w-5 sm:h-5 text-cyber-blue" />;
      case 'user':
      case 'TARGET':
      case 'VICTIM_GATEWAY':
        return <User className="w-4 h-4 sm:w-5 sm:h-5 text-cyber-green" />;
      case 'malware':
        return <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-cyber-red" />;
      default:
        return <Globe className="w-4 h-4 sm:w-5 sm:h-5 text-cyber-blue" />;
    }
  };

  const getNodeColor = (type: GraphNode['type']) => {
    switch (type) {
      case 'attacker':
      case 'INFRASTRUCTURE':
      case 'INTERNAL_SOURCE':
        return 'border-cyber-red bg-cyber-red/10 cyber-glow-red';
      case 'domain':
      case 'DECEPTIVE_DOMAIN':
      case 'CREDENTIAL_HARVESTER':
        return 'border-[#f59e0b] bg-[#f59e0b]/10';
      case 'email':
      case 'IDENTITY':
      case 'EXFILTRATION_MAILBOX':
        return 'border-cyber-blue bg-cyber-blue/10 cyber-glow-blue';
      case 'user':
      case 'TARGET':
      case 'VICTIM_GATEWAY':
        return 'border-cyber-green bg-cyber-green/10';
      case 'malware':
        return 'border-cyber-red bg-cyber-red/20 cyber-glow-red animate-pulse';
      default:
        return 'border-cyber-blue bg-cyber-blue/10';
    }
  };

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-3">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-xl sm:text-2xl font-mono text-cyber-text tracking-tight mb-1">
              {t('attack_graph_title')}
            </h2>
            {sourceMode === 'live_forensics' && (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-[0_0_10px_rgba(0,245,255,0.2)]">
                {t('live_forensic_session')}
              </span>
            )}
          </div>
          <p className="text-cyber-muted text-xs sm:text-sm">
            {t('attack_graph_desc')}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {sourceMode === 'live_forensics' && (
            <Button onClick={resetToSample} variant="outline" size="sm" className="font-mono text-xs text-cyber-muted hover:text-white">
              <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> {t('default_campaign')}
            </Button>
          )}
          <div className="flex items-center bg-[#05080f] rounded-lg border border-white/10 p-0.5">
            <button
              onClick={() => setZoomLevel(prev => Math.max(0.7, prev - 0.15))}
              className="p-1.5 hover:bg-white/10 rounded text-gray-400 hover:text-white"
              title={t('zoom_out')}
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="text-[10px] font-mono text-gray-400 px-2">{Math.round(zoomLevel * 100)}%</span>
            <button
              onClick={() => setZoomLevel(prev => Math.min(1.6, prev + 0.15))}
              className="p-1.5 hover:bg-white/10 rounded text-gray-400 hover:text-white"
              title={t('zoom_in')}
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="p-1.5 hover:bg-white/10 rounded text-gray-400 hover:text-white"
              title={t('reset_zoom')}
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas & Inspector Layout */}
      <div className="flex-1 flex flex-col lg:flex-row gap-4 min-h-0">
        {/* Canvas Graph Area */}
        <Card className="flex-[3] relative overflow-hidden bg-[#05080f] border-cyber-border/50 min-h-[420px] lg:min-h-[500px] flex flex-col">
          <div className="radar-bg"></div>
          
          {/* Canvas Legend */}
          <div className="absolute top-3 left-3 z-20 flex items-center gap-3 bg-[#0a0f1c]/80 backdrop-blur-md px-3 py-1.5 rounded-lg border border-white/10 text-[10px] font-mono text-gray-300 overflow-x-auto max-w-[calc(100%-24px)]">
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyber-red" /> {t('legend_threat_mta')}</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#f59e0b]" /> {t('legend_deceptive_domain')}</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyber-blue" /> {t('legend_claimed_sender')}</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyber-green" /> {t('legend_target_gateway')}</span>
          </div>

          <CardContent ref={canvasRef} className="h-full p-0 relative flex-1 overflow-hidden">
            <div
              className="absolute inset-0 transition-transform duration-200 origin-center"
              style={{ transform: `scale(${zoomLevel})` }}
            >
              {/* Dynamic SVG Connection Vectors */}
              <svg className="absolute inset-0 w-full h-full pointer-events-none">
                <defs>
                  <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                    <polygon points="0 0, 8 3, 0 6" fill="rgba(255,255,255,0.25)" />
                  </marker>
                  <marker id="arrowhead-active" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                    <polygon points="0 0, 8 3, 0 6" fill="#00f5ff" />
                  </marker>
                  <marker id="arrowhead-threat" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                    <polygon points="0 0, 8 3, 0 6" fill="#ef4444" />
                  </marker>
                </defs>
                {edges.map((edge, i) => {
                  const source = nodes.find(n => n.id === edge.source);
                  const target = nodes.find(n => n.id === edge.target);
                  if (!source || !target) return null;
                  const isSelected = selectedNode?.id === source.id || selectedNode?.id === target.id;
                  
                  return (
                    <g key={`edge-${i}`}>
                      <motion.line
                        x1={`${source.x}%`} y1={`${source.y}%`}
                        x2={`${target.x}%`} y2={`${target.y}%`}
                        stroke={isSelected ? '#00f5ff' : 'rgba(255,255,255,0.18)'}
                        strokeWidth={isSelected ? 2.5 : 1.5}
                        strokeDasharray={edge.type === 'phished' || edge.type === 'payload' ? '4 3' : undefined}
                        markerEnd={isSelected ? "url(#arrowhead-active)" : "url(#arrowhead)"}
                        initial={{ pathLength: 0 }}
                        animate={{ pathLength: 1 }}
                        transition={{ duration: 0.8, delay: i * 0.1 }}
                      />
                      {/* Edge Label on Midpoint */}
                      <text
                        x={`${(source.x + target.x) / 2}%`}
                        y={`${(source.y + target.y) / 2 - 2}%`}
                        fill={isSelected ? '#00f5ff' : 'rgba(156, 163, 175, 0.7)'}
                        fontSize="9"
                        fontFamily="monospace"
                        textAnchor="middle"
                        className="pointer-events-none select-none font-bold"
                      >
                        {edge.relationship || edge.type || ''}
                      </text>
                    </g>
                  );
                })}
              </svg>

              {/* Node Vertices */}
              {nodes.map((node) => {
                const isSelected = selectedNode?.id === node.id;
                return (
                  <motion.div
                    key={node.id}
                    className={`absolute w-10 h-10 sm:w-12 sm:h-12 -ml-5 -mt-5 sm:-ml-6 sm:-mt-6 rounded-full border-2 flex items-center justify-center cursor-pointer transition-all z-10 ${getNodeColor(node.type)} ${
                      isSelected ? 'scale-125 ring-4 ring-cyber-blue shadow-[0_0_20px_rgba(0,245,255,0.6)] z-20' : 'hover:scale-110'
                    }`}
                    style={{ left: `${node.x}%`, top: `${node.y}%` }}
                    onClick={() => setSelectedNode(node)}
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: isSelected ? 1.2 : 1, opacity: 1 }}
                    transition={{ type: "spring" as any, stiffness: 220, damping: 20 }}
                  >
                    {getNodeIcon(node.type)}
                    
                    {/* Node Tag Tooltip below */}
                    <div className={`absolute top-11 sm:top-13 whitespace-nowrap font-mono text-[9px] sm:text-[10px] px-2 py-0.5 rounded border max-w-[160px] sm:max-w-[200px] truncate shadow-lg pointer-events-none transition-all ${
                      isSelected
                        ? 'bg-cyber-blue text-black font-bold border-cyber-blue shadow-[0_0_12px_rgba(0,245,255,0.4)]'
                        : 'bg-[#0a0f1c]/90 text-gray-200 border-white/10'
                    }`}>
                      {node.label}
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Forensic Entity Inspector Card */}
        <Card className="flex-[1] flex flex-col bg-[#0a0f1c] border-cyber-border/50 shadow-2xl">
          <CardContent className="p-5 font-mono h-full flex flex-col justify-between space-y-4">
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyber-blue" />
                  <h3 className="text-cyber-blue font-bold text-xs uppercase tracking-widest">
                    {t('forensic_inspector')}
                  </h3>
                </div>
                <span className="text-[10px] text-gray-500 font-mono">{t('node_telemetry')}</span>
              </div>

              {selectedNode ? (
                <div className="space-y-4">
                  <div>
                    <span className="text-gray-400 text-[10px] block mb-1">{t('entity_classification')}</span>
                    <span className="text-white text-xs uppercase px-2.5 py-1 bg-[#05080f] border border-white/10 rounded inline-block font-bold">
                      {selectedNode.type}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-400 text-[10px] block mb-1">{t('identifier_label')}</span>
                    <div className="text-cyber-blue text-xs break-all bg-[#05080f] p-2.5 rounded-lg border border-white/10 font-mono font-bold">
                      {selectedNode.label}
                    </div>
                  </div>
                  {selectedNode.details && (
                    <div>
                      <span className="text-gray-400 text-[10px] block mb-1">{t('evidence_details')}</span>
                      <p className="text-xs text-gray-200 leading-relaxed bg-[#05080f] p-3 rounded-lg border border-white/10">
                        {selectedNode.details}
                      </p>
                    </div>
                  )}
                  <div>
                    <span className="text-gray-400 text-[10px] block mb-1">{t('relational_hops')}</span>
                    <ul className="text-xs space-y-2 max-h-48 overflow-y-auto pr-1">
                      {edges.filter(e => e.source === selectedNode.id).map((e, idx) => {
                        const peer = nodes.find(n => n.id === e.target);
                        return (
                          <li key={`out-${idx}`} className="text-gray-300 bg-[#05080f] p-2 rounded border border-white/5 flex items-center justify-between gap-2">
                            <span className="text-cyber-red text-[10px] font-bold uppercase shrink-0">➔ {e.relationship || e.type || 'LINK'}:</span>
                            <span className="text-white text-[11px] truncate">{peer?.label || e.target}</span>
                          </li>
                        );
                      })}
                      {edges.filter(e => e.target === selectedNode.id).map((e, idx) => {
                        const peer = nodes.find(n => n.id === e.source);
                        return (
                          <li key={`in-${idx}`} className="text-gray-300 bg-[#05080f] p-2 rounded border border-white/5 flex items-center justify-between gap-2">
                            <span className="text-cyber-green text-[10px] font-bold uppercase shrink-0">⬅ {e.relationship || e.type || 'LINK'}:</span>
                            <span className="text-white text-[11px] truncate">{peer?.label || e.source}</span>
                          </li>
                        );
                      })}
                      {edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).length === 0 && (
                        <li className="text-gray-500 text-[11px] italic p-2 bg-[#05080f] rounded">
                          {t('isolated_vertex')}
                        </li>
                      )}
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center text-gray-400 text-xs text-center border border-dashed border-white/10 rounded-xl p-6 my-6 space-y-2">
                  <AlertTriangle className="w-6 h-6 text-cyber-blue" />
                  <p>{t('select_node_prompt')}</p>
                </div>
              )}
            </div>
            
            <div className="pt-4 border-t border-white/10 text-[10px] text-gray-400 flex justify-between items-center">
              <span>{t('nodes_label')}: <strong className="text-white">{nodes.length}</strong></span>
              <span>{t('edges_label')}: <strong className="text-white">{edges.length}</strong></span>
              <span>{t('mode_label')}: <strong className="text-cyber-blue uppercase">{sourceMode}</strong></span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

