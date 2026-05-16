import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Card, CardContent } from '@/components/ui/card';
import { Network, Server, User, Mail, Link as LinkIcon, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface Node {
  id: string;
  type: 'domain' | 'email' | 'user' | 'attacker' | 'malware';
  label: string;
  x: number;
  y: number;
}

interface Edge {
  source: string;
  target: string;
  type: 'phished' | 'hosted' | 'sent' | 'payload';
}

const nodes: Node[] = [
  { id: 'n1', type: 'attacker', label: '192.168.45.2', x: 10, y: 50 },
  { id: 'n2', type: 'domain', label: 'paypal-secure-update.net', x: 30, y: 20 },
  { id: 'n3', type: 'domain', label: 'microsoft-login-verify.com', x: 30, y: 80 },
  { id: 'n4', type: 'email', label: 'billing@paypal.com (Spoof)', x: 50, y: 20 },
  { id: 'n5', type: 'email', label: 'admin@microsoft.com (Spoof)', x: 50, y: 80 },
  { id: 'n6', type: 'user', label: 'finance-team', x: 75, y: 20 },
  { id: 'n7', type: 'user', label: 'exec-board', x: 75, y: 80 },
  { id: 'n8', type: 'malware', label: 'AgentTesla.exe', x: 90, y: 50 },
];

const edges: Edge[] = [
  { source: 'n1', target: 'n2', type: 'hosted' },
  { source: 'n1', target: 'n3', type: 'hosted' },
  { source: 'n2', target: 'n4', type: 'sent' },
  { source: 'n3', target: 'n5', type: 'sent' },
  { source: 'n4', target: 'n6', type: 'phished' },
  { source: 'n5', target: 'n7', type: 'phished' },
  { source: 'n6', target: 'n8', type: 'payload' },
];

export function AttackGraph() {
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);

  const getNodeIcon = (type: Node['type']) => {
    switch (type) {
      case 'attacker': return <Server className="w-5 h-5 text-cyber-red" />;
      case 'domain': return <LinkIcon className="w-5 h-5 text-[#f59e0b]" />;
      case 'email': return <Mail className="w-5 h-5 text-cyber-blue" />;
      case 'user': return <User className="w-5 h-5 text-cyber-green" />;
      case 'malware': return <Shield className="w-5 h-5 text-cyber-red" />;
    }
  };

  const getNodeColor = (type: Node['type']) => {
    switch (type) {
      case 'attacker': return 'border-cyber-red bg-cyber-red/10 cyber-glow-red';
      case 'domain': return 'border-[#f59e0b] bg-[#f59e0b]/10';
      case 'email': return 'border-cyber-blue bg-cyber-blue/10 cyber-glow-blue';
      case 'user': return 'border-cyber-green bg-cyber-green/10';
      case 'malware': return 'border-cyber-red bg-cyber-red/20 cyber-glow-red animate-pulse';
    }
  };

  return (
    <div className="flex flex-col h-full space-y-4">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-2xl font-mono text-cyber-text tracking-tight mb-1">ATTACK GRAPH EXPLORER</h2>
          <p className="text-cyber-muted text-sm">Visualize domain relationships, email origins, and payload distribution.</p>
        </div>
        <div className="flex space-x-2">
          <Button variant="outline" size="sm" className="font-mono text-xs"><Network className="w-4 h-4 mr-2" /> RECALCULATE LAYOUT</Button>
        </div>
      </div>

      <div className="flex-1 flex space-x-4 min-h-0">
        <Card className="flex-[3] relative overflow-hidden bg-cyber-bg/50 border-cyber-border/50">
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
                const source = nodes.find(n => n.id === edge.source)!;
                const target = nodes.find(n => n.id === edge.target)!;
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
                    transition={{ duration: 1.5, delay: i * 0.2 }}
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
                <div className="absolute top-14 whitespace-nowrap font-mono text-[10px] text-cyber-text bg-cyber-panel/80 px-2 py-1 rounded border border-cyber-border/50">
                  {node.label}
                </div>
              </motion.div>
            ))}
          </CardContent>
        </Card>

        <Card className="flex-[1] flex flex-col">
          <CardContent className="p-6 font-mono h-full flex flex-col">
            <h3 className="text-cyber-blue font-bold mb-4 border-b border-cyber-border pb-2 block">INSPECTOR</h3>
            {selectedNode ? (
              <div className="space-y-4">
                <div>
                  <span className="text-cyber-muted text-[10px] block mb-1">ENTITY TYPE</span>
                  <span className="text-cyber-text text-sm uppercase px-2 py-1 bg-cyber-panel border border-cyber-border rounded inline-block">{selectedNode.type}</span>
                </div>
                <div>
                  <span className="text-cyber-muted text-[10px] block mb-1">IDENTIFIER</span>
                  <span className="text-cyber-blue text-xs break-all">{selectedNode.label}</span>
                </div>
                <div>
                  <span className="text-cyber-muted text-[10px] block mb-1">CONNECTIONS</span>
                  <ul className="text-xs space-y-1">
                    {edges.filter(e => e.source === selectedNode.id).map(e => {
                      const peer = nodes.find(n => n.id === e.target)!;
                      return <li key={e.target} className="text-cyber-muted"><span className="text-cyber-red">Out:</span> {e.type} {"->"} <span className="text-cyber-text">{peer.label}</span></li>
                    })}
                    {edges.filter(e => e.target === selectedNode.id).map(e => {
                      const peer = nodes.find(n => n.id === e.source)!;
                      return <li key={e.source} className="text-cyber-muted"><span className="text-cyber-green">In:</span> {e.type} {"<-"} <span className="text-cyber-text">{peer.label}</span></li>
                    })}
                  </ul>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center text-cyber-muted text-xs text-center border border-dashed border-cyber-border/50 rounded-lg p-4">
                Select a node on the graph to view intelligence details and threat indicators.
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
