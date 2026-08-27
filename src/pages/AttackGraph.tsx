import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Card, CardContent } from '@/components/ui/card';
import { Network, Server, User, Mail, Link as LinkIcon, Shield, Globe, RefreshCw, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';

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
  { id: 'n2', type: 'domain', label: 'm1crosoft-support.com', x: 30, y: 25, details: 'Typosquatted domain with homoglyph numeral 1' },
  { id: 'n3', type: 'domain', label: 'microsoft-security-verification.example.com', x: 30, y: 75, details: 'Credential harvester landing host' },
  { id: 'n4', type: 'email', label: 'security@m1crosoft-support.com', x: 55, y: 25, details: 'Forged header sender claiming Microsoft Security' },
  { id: 'n5', type: 'email', label: 'microsoft.verify.account@gmail.com', x: 55, y: 75, details: 'Exfiltration reply-to mailbox' },
  { id: 'n6', type: 'user', label: 'mx.company.com (Gateway)', x: 75, y: 50, details: 'Target enterprise perimeter boundary MX' },
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
  const [nodes, setNodes] = useState<GraphNode[]>(defaultNodes);
  const [edges, setEdges] = useState<GraphEdge[]>(defaultEdges);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [sourceMode, setSourceMode] = useState<'sample' | 'live_forensics'>('sample');

  const loadActiveGraph = () => {
    try {
      const storedGraph = localStorage.getItem('neuroshield_active_attack_graph');
      if (storedGraph) {
        const parsed = JSON.parse(storedGraph);
        if (parsed.nodes && parsed.nodes.length > 0) {
          setNodes(parsed.nodes);
          setEdges(parsed.edges || []);
          setSourceMode('live_forensics');
          setSelectedNode(parsed.nodes[0] || null);
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
  };

  const getNodeIcon = (type: GraphNode['type']) => {
    switch (type) {
      case 'attacker':
      case 'INFRASTRUCTURE':
      case 'INTERNAL_SOURCE':
        return <Server className="w-5 h-5 text-cyber-red" />;
      case 'domain':
      case 'DECEPTIVE_DOMAIN':
      case 'CREDENTIAL_HARVESTER':
        return <LinkIcon className="w-5 h-5 text-[#f59e0b]" />;
      case 'email':
      case 'IDENTITY':
      case 'EXFILTRATION_MAILBOX':
        return <Mail className="w-5 h-5 text-cyber-blue" />;
      case 'user':
      case 'TARGET':
      case 'VICTIM_GATEWAY':
        return <User className="w-5 h-5 text-cyber-green" />;
      case 'malware':
        return <Shield className="w-5 h-5 text-cyber-red" />;
      default:
        return <Globe className="w-5 h-5 text-cyber-blue" />;
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
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-2xl font-mono text-cyber-text tracking-tight mb-1">ATTACK GRAPH EXPLORER</h2>
            {sourceMode === 'live_forensics' && (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40">
                LIVE FORENSICS DOSSIER
              </span>
            )}
          </div>
          <p className="text-cyber-muted text-sm">Visualize domain relationships, email origin hops, and attacker infrastructure clusters.</p>
        </div>
        <div className="flex space-x-2">
          {sourceMode === 'live_forensics' && (
            <Button onClick={resetToSample} variant="outline" size="sm" className="font-mono text-xs text-cyber-muted hover:text-white">
              <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> LOAD DEFAULT CAMPAIGN
            </Button>
          )}
          <Button variant="outline" size="sm" className="font-mono text-xs">
            <Network className="w-4 h-4 mr-2" /> RECALCULATE TOPOLOGY
          </Button>
        </div>
      </div>

      <div className="flex-1 flex flex-col lg:flex-row space-y-4 lg:space-y-0 lg:space-x-4 min-h-0">
        <Card className="flex-[3] relative overflow-hidden bg-cyber-bg/50 border-cyber-border/50 min-h-[420px]">
          <div className="radar-bg"></div>
          
          <CardContent className="h-full p-0 relative">
            <svg className="absolute inset-0 w-full h-full pointer-events-none">
              <defs>
                <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="var(--color-cyber-muted)" />
                </marker>
                <marker id="arrowhead-active" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="var(--color-cyber-red)" />
                </marker>
              </defs>
              {edges.map((edge, i) => {
                const source = nodes.find(n => n.id === edge.source);
                const target = nodes.find(n => n.id === edge.target);
                if (!source || !target) return null;
                const isSelected = selectedNode?.id === source.id || selectedNode?.id === target.id;
                
                return (
                  <motion.line
                    key={i}
                    x1={`${source.x}%`} y1={`${source.y}%`}
                    x2={`${target.x}%`} y2={`${target.y}%`}
                    stroke={isSelected ? 'var(--color-cyber-red)' : 'var(--color-cyber-border)'}
                    strokeWidth={isSelected ? 2 : 1}
                    markerEnd={isSelected ? "url(#arrowhead-active)" : "url(#arrowhead)"}
                    initial={{ pathLength: 0 }}
                    animate={{ pathLength: 1 }}
                    transition={{ duration: 1.2, delay: i * 0.15 }}
                  />
                );
              })}
            </svg>

            {nodes.map((node) => (
              <motion.div
                key={node.id}
                className={`absolute w-12 h-12 -ml-6 -mt-6 rounded-full border-2 flex items-center justify-center cursor-pointer transition-transform hover:scale-110 z-10 ${getNodeColor(node.type)} ${selectedNode?.id === node.id ? 'scale-110 ring-4 ring-cyber-border' : ''}`}
                style={{ left: `${node.x}%`, top: `${node.y}%` }}
                onClick={() => setSelectedNode(node)}
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ type: "spring" as any, stiffness: 200, damping: 20 }}
              >
                {getNodeIcon(node.type)}
                <div className="absolute top-14 whitespace-nowrap font-mono text-[10px] text-cyber-text bg-cyber-panel/90 px-2 py-1 rounded border border-cyber-border/50 max-w-[200px] truncate shadow-lg">
                  {node.label}
                </div>
              </motion.div>
            ))}
          </CardContent>
        </Card>

        <Card className="flex-[1] flex flex-col bg-[#05080f] border-cyber-border/50">
          <CardContent className="p-5 font-mono h-full flex flex-col justify-between">
            <div>
              <h3 className="text-cyber-blue font-bold text-xs uppercase tracking-widest mb-4 border-b border-cyber-border pb-2 flex items-center justify-between">
                <span>FORENSIC INSPECTOR</span>
                <Shield className="w-3.5 h-3.5 text-cyber-blue" />
              </h3>
              {selectedNode ? (
                <div className="space-y-4">
                  <div>
                    <span className="text-cyber-muted text-[10px] block mb-1">ENTITY CLASSIFICATION</span>
                    <span className="text-cyber-text text-xs uppercase px-2.5 py-1 bg-cyber-panel border border-cyber-border rounded inline-block font-bold">
                      {selectedNode.type}
                    </span>
                  </div>
                  <div>
                    <span className="text-cyber-muted text-[10px] block mb-1">IDENTIFIER / LABEL</span>
                    <div className="text-cyber-blue text-xs break-all bg-black/40 p-2 rounded border border-white/5 font-mono">
                      {selectedNode.label}
                    </div>
                  </div>
                  {selectedNode.details && (
                    <div>
                      <span className="text-cyber-muted text-[10px] block mb-1">EVIDENCE DETAILS</span>
                      <p className="text-xs text-gray-300 leading-relaxed bg-white/5 p-2 rounded border border-white/5">
                        {selectedNode.details}
                      </p>
                    </div>
                  )}
                  <div>
                    <span className="text-cyber-muted text-[10px] block mb-1">RELATIONAL TOPOLOGY</span>
                    <ul className="text-xs space-y-1.5 max-h-40 overflow-y-auto pr-1">
                      {edges.filter(e => e.source === selectedNode.id).map((e, idx) => {
                        const peer = nodes.find(n => n.id === e.target);
                        return (
                          <li key={`out-${idx}`} className="text-gray-400 bg-black/20 p-1.5 rounded border border-white/5 flex items-center justify-between">
                            <span className="text-cyber-red text-[11px] font-bold">Out [{e.relationship || e.type || 'LINK'}]:</span>
                            <span className="text-cyber-text text-[11px] truncate max-w-[120px]">{peer?.label || e.target}</span>
                          </li>
                        );
                      })}
                      {edges.filter(e => e.target === selectedNode.id).map((e, idx) => {
                        const peer = nodes.find(n => n.id === e.source);
                        return (
                          <li key={`in-${idx}`} className="text-gray-400 bg-black/20 p-1.5 rounded border border-white/5 flex items-center justify-between">
                            <span className="text-cyber-green text-[11px] font-bold">In [{e.relationship || e.type || 'LINK'}]:</span>
                            <span className="text-cyber-text text-[11px] truncate max-w-[120px]">{peer?.label || e.source}</span>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center text-cyber-muted text-xs text-center border border-dashed border-cyber-border/50 rounded-lg p-6 my-6">
                  <AlertTriangle className="w-6 h-6 text-cyber-muted mb-2" />
                  Select any node on the graph canvas to inspect technical attribution and relational telemetry.
                </div>
              )}
            </div>
            
            <div className="pt-4 border-t border-cyber-border/50 text-[10px] text-cyber-muted">
              Total Nodes: <span className="text-white font-bold">{nodes.length}</span> | Connected Edges: <span className="text-white font-bold">{edges.length}</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

