import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldOff, Server, Laptop, Database, Globe, Network, Shield, AlertTriangle, Mail, Link2, Ghost, Lock
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { addScanToHistory } from '@/lib/history';

interface Node {
  id: string;
  type: string;
  label: string;
  ip: string;
  x: number;
  y: number;
  status: 'clean' | 'threat' | 'isolated';
}

interface Packet {
  id: string;
  from: string;
  to: string;
  protocol: string;
  size: string;
  threat: boolean;
}

interface Edge {
  from: string;
  to: string;
}

const initialNodes: Node[] = [
  { id: 'attacker', type: 'attacker', label: 'Attacker Origin', ip: 'Unknown [TOR]', x: 10, y: 50, status: 'clean' },
  { id: 'email', type: 'email', label: 'Email Gateway', ip: 'mail.server.net', x: 30, y: 25, status: 'clean' },
  { id: 'link', type: 'link', label: 'Malicious Link', ip: 'http://evilsite.xyz', x: 50, y: 75, status: 'clean' },
  { id: 'user', type: 'user', label: 'Victim Device', ip: '192.168.1.100', x: 70, y: 25, status: 'clean' },
  { id: 'theft', type: 'theft', label: 'Data Exfiltration', ip: 'Remote Dropzone', x: 90, y: 50, status: 'clean' },
];

const edges: Edge[] = [
  { from: 'attacker', to: 'email' },
  { from: 'email', to: 'link' },
  { from: 'link', to: 'user' },
  { from: 'user', to: 'theft' }
];

export default function SentinelWaveModule() {
  const [nodes, setNodes] = useState<Node[]>(initialNodes);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [log, setLog] = useState<{ time: string; msg: string; type: 'info' | 'warn' | 'crit' }[]>([]);

  const nodesRef = useRef(nodes);
  const stepRef = useRef(0);
  const resetTimerRef = useRef<any>(null);

  useEffect(() => {
    nodesRef.current = nodes;
  }, [nodes]);

  // Simulation: Move packets along edges sequentially to simulate the attack path
  useEffect(() => {
    const packetInterval = setInterval(() => {
       const currentNodes = nodesRef.current;
       const step = stepRef.current;

       if (step >= edges.length) {
          if (!resetTimerRef.current) {
            resetTimerRef.current = setTimeout(() => {
               setNodes(curr => curr.map(n => n.status === 'isolated' ? n : { ...n, status: 'clean' }));
               setLog(prev => [{ time: new Date().toLocaleTimeString(), msg: '[SYSTEM] Topology sequence reset.', type: 'info' }, ...prev.slice(0, 50)]);
               stepRef.current = 0;
               resetTimerRef.current = null;
            }, 6000);
          }
          return;
       }

       const edge = edges[step];
       const sourceNode = currentNodes.find(n => n.id === edge.from);

       if (sourceNode?.status === 'isolated') {
           setLog(prev => [{ time: new Date().toLocaleTimeString(), msg: `[DEFENSE] Threat mitigated. Attack halted at isolated node.`, type: 'info' }, ...prev.slice(0, 50)]);
           stepRef.current = edges.length; // end sequence
           return;
       }

       const newPacket: Packet = {
          id: Math.random().toString(36).substr(2, 9),
          from: edge.from,
          to: edge.to,
          protocol: step === 0 ? 'SMTP' : step === 1 ? 'HTTP' : step === 2 ? 'TCP' : 'TLS_EXFIL',
          size: Math.floor(Math.random() * 1500) + ' bytes',
          threat: true
       };

       setPackets(prev => [...prev.slice(-20), newPacket]);

       setNodes(curr => curr.map(n => 
          n.id === edge.to && n.status !== 'isolated' ? { ...n, status: 'threat' } : n
       ));

       const messages = [
         `Attacker dispatched phishing payload via SMTP`,
         `Email delivered, malicious link embedded in message`,
         `Victim clicked link, payload executed on device`,
         `Data exfiltration initiated to remote attacker database`
       ];

       setLog(prev => [{
         time: new Date().toLocaleTimeString(),
         msg: messages[step],
         type: 'crit'
       }, ...prev.slice(0, 50)]);

       stepRef.current = step + 1;
    }, 2500);

    return () => {
       clearInterval(packetInterval);
       clearTimeout(resetTimerRef.current);
    };
  }, []);

  const isolateThreat = (nodeId: string) => {
    setNodes(curr => curr.map(n => n.id === nodeId ? { ...n, status: 'isolated' } : n));
    setLog(prev => [{
      time: new Date().toLocaleTimeString(),
      msg: `CONNECTION SEVERED: Node ${nodeId} quarantined.`,
      type: 'warn'
    }, ...prev.slice(0, 50)]);
    setSelectedNode(prev => prev && prev.id === nodeId ? { ...prev, status: 'isolated' } : prev);
    addScanToHistory({
      detectedType: 'NETWORK_LOG',
      riskScore: 90,
      signals: ['MALICIOUS TRAFFIC DETECTED', 'NODE COMPROMISED', 'PAYLOAD INTERCEPTED'],
      source: 'Network Scanner',
      target: nodeId,
      payloadDescription: `Ancillary scanning detected lateral movement originating from or targeting node ${nodeId}. Auto-isolation engaged.`,
      threatName: 'Lateral Network Exfiltration'
    });
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'attacker': return <Ghost className="w-6 h-6" />;
      case 'email': return <Mail className="w-6 h-6" />;
      case 'link': return <Link2 className="w-6 h-6" />;
      case 'user': return <Laptop className="w-6 h-6" />;
      case 'theft': return <Database className="w-6 h-6" />;
      default: return <Server className="w-6 h-6" />;
    }
  };

  return (
    <div className="flex-1 flex flex-col md:flex-row h-full overflow-hidden bg-[#020408] p-4 lg:p-6 gap-6 relative">
      {/* Node Graph Centerpiece */}
      <div className="flex-1 relative overflow-hidden bg-[#0a0d1a] border border-[#00f5ff]/20 rounded-2xl shadow-[inset_0_0_50px_rgba(0,245,255,0.05)] group">
        <div className="absolute top-6 left-6 z-10 flex gap-4">
          <div className="bg-black/50 border border-white/10 px-4 py-2 rounded-lg backdrop-blur-md">
            <h2 className="text-2xl font-black tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-white to-[#00f5ff] uppercase">
              Sentinel Wave
            </h2>
            <p className="text-[10px] text-[#00f5ff] font-mono tracking-[0.2em] mt-1 drop-shadow-[0_0_5px_#00f5ff]">TOPOLOGY VISUALIZER</p>
          </div>
        </div>

        {/* Visualizer SVG */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <defs>
            <filter id="glowWave" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="6" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <linearGradient id="edgeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
               <stop offset="0%" stopColor="rgba(0, 245, 255, 0.1)" />
               <stop offset="100%" stopColor="rgba(0, 255, 102, 0.4)" />
            </linearGradient>
            <linearGradient id="edgeGradientAlert" x1="0%" y1="0%" x2="100%" y2="0%">
               <stop offset="0%" stopColor="rgba(255, 42, 85, 0.5)" />
               <stop offset="100%" stopColor="rgba(255, 42, 85, 0.8)" />
            </linearGradient>
          </defs>
          
          {/* Decorative Grid Lines */}
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
             <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="1"/>
          </pattern>
          <rect width="100%" height="100%" fill="url(#grid)" />

          {/* Connections */}
          {edges.map((edge) => {
            const source = nodes.find(n => n.id === edge.from);
            const target = nodes.find(n => n.id === edge.to);
            if (!source || !target) return null;

            const isSourceIsolated = source.status === 'isolated';
            const isTargetIsolated = target.status === 'isolated';
            if (isSourceIsolated || isTargetIsolated) return null;

            const isUnderAttack = target.status === 'threat' || source.status === 'threat';

            return (
              <line
                key={`${source.id}-${target.id}`}
                x1={`${source.x}%`}
                y1={`${source.y}%`}
                x2={`${target.x}%`}
                y2={`${target.y}%`}
                stroke={isUnderAttack ? "url(#edgeGradientAlert)" : "url(#edgeGradient)"}
                strokeWidth={isUnderAttack ? "2" : "1.5"}
                strokeDasharray={isUnderAttack ? "none" : "5,5"}
                className={isUnderAttack ? "animate-pulse" : ""}
              />
            );
          })}

          {/* Animating Packets */}
          <AnimatePresence>
            {packets.map((p) => {
              const fromNode = nodes.find(n => n.id === p.from);
              const toNode = nodes.find(n => n.id === p.to);
              if (!fromNode || !toNode || fromNode.status === 'isolated' || toNode.status === 'isolated') return null;

              return (
                <motion.circle
                  key={p.id}
                  r={p.threat ? 5 : 3}
                  fill={p.threat ? '#ff2a55' : '#00f5ff'}
                  initial={{ cx: `${fromNode.x}%`, cy: `${fromNode.y}%`, opacity: 0 }}
                  animate={{ cx: `${toNode.x}%`, cy: `${toNode.y}%`, opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 1.2, ease: "linear" }}
                  style={{ filter: 'url(#glowWave)' }}
                />
              );
            })}
          </AnimatePresence>
        </svg>

        {/* Node Components */}
        {nodes.map((node) => (
          <motion.div
            key={node.id}
            initial={false}
            animate={{ 
               scale: node.status === 'threat' ? [1, 1.15, 1] : 1,
               y: node.status === 'clean' ? [0, -5, 0] : 0 
            }}
            transition={{ 
               duration: node.status === 'threat' ? 0.4 : 4, 
               repeat: Infinity,
               ease: "easeInOut",
               delay: node.id.length * 0.2 // stagger float
            }}
            className={cn(
               "absolute -translate-x-1/2 -translate-y-1/2 cursor-pointer z-20 group/node",
               node.id === 'gw' ? "z-30 scale-125" : ""
            )}
            style={{ left: `${node.x}%`, top: `${node.y}%` }}
            onClick={() => setSelectedNode(node)}
          >
            <div className={cn(
               "relative p-4 rounded-xl border backdrop-blur-xl transition-all duration-300 flex items-center justify-center",
               node.status === 'threat' ? 'border-[#ff2a55] bg-[#ff2a55]/20 shadow-[0_0_30px_#ff2a55]' : 
               node.status === 'isolated' ? 'border-white/20 bg-black/60 opacity-60' :
               node.id === 'gw' ? 'border-[#00f5ff] bg-[#00f5ff]/10 shadow-[0_0_20px_var(--color-cyber-blue-glow)]' :
               'border-[#00ff66]/40 bg-[#00ff66]/10 hover:border-[#00ff66] hover:shadow-[0_0_15px_rgba(0,255,102,0.3)]'
            )}>
              <div className={cn(
                 "transition-colors",
                 node.status === 'threat' ? 'text-[#ff2a55]' : 
                 node.status === 'isolated' ? 'text-gray-500' :
                 node.id === 'gw' ? 'text-[#00f5ff]' : 'text-[#00ff66]'
              )}>
                {node.status === 'isolated' ? <ShieldOff className="w-6 h-6" /> : getIcon(node.type)}
              </div>
              
              {/* Threat pulse rings */}
              {node.status === 'threat' && (
                 <div className="absolute inset-0 border border-[#ff2a55] rounded-xl animate-ping opacity-50" />
              )}
            </div>
            
            <div className={cn(
               "absolute left-1/2 -translate-x-1/2 mt-3 whitespace-nowrap flex flex-col items-center pointer-events-none transition-all",
               node.id === 'gw' ? "top-14" : "top-12"
            )}>
               <span className="text-[9px] font-mono font-bold text-white uppercase tracking-widest bg-black/80 px-2 py-0.5 rounded border border-white/10 shadow-lg">
                 {node.label}
               </span>
               <span className="text-[8px] font-mono text-[#8a99af] mt-1 tracking-wider">
                 {node.ip}
               </span>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Right Sidebar UI */}
      <div className="w-full md:w-80 flex flex-col gap-6">
        {/* Selected Node Inspector */}
        <Card className="bg-[#0a0d1a] border-[#00f5ff]/20 backdrop-blur-xl relative overflow-hidden flex-shrink-0 shadow-[0_10px_30px_rgba(0,0,0,0.5)]">
          <CardContent className="p-5">
            <div className="flex items-center justify-between mb-4 pb-2 border-b border-white/10">
               <h3 className="text-xs font-mono tracking-[0.2em] font-bold uppercase text-[#00f5ff]">Node Analysis</h3>
               <div className="flex gap-1">
                  <span className="w-2 h-2 rounded-full bg-[#ff2a55]" />
                  <span className="w-2 h-2 rounded-full bg-[#ffea00]" />
                  <span className="w-2 h-2 rounded-full bg-[#00ff66]" />
               </div>
            </div>
            {selectedNode ? (
              <div className="space-y-5">
                <div className="flex items-center gap-4">
                  <div className={cn(
                     "p-3 rounded-xl border flex-shrink-0", 
                     selectedNode.status === 'threat' ? 'border-[#ff2a55] bg-[#ff2a55]/20 text-[#ff2a55] shadow-[0_0_15px_#ff2a55]' : 
                     selectedNode.status === 'isolated' ? 'border-gray-500 bg-gray-900 text-gray-500' :
                     'text-[#00ff66] border-[#00ff66]/30 bg-[#00ff66]/10'
                  )}>
                    {getIcon(selectedNode.type)}
                  </div>
                  <div>
                    <div className="text-sm font-bold text-white tracking-widest uppercase">{selectedNode.label}</div>
                    <div className="text-xs text-[#8a99af] font-mono">{selectedNode.ip}</div>
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-3 text-[10px] font-mono">
                  <div className="bg-black/50 p-3 rounded border border-white/10">
                    <div className="opacity-50 mb-1 uppercase tracking-widest">Inbound Traffic</div>
                    <div className="text-[#00f5ff] font-bold tracking-widest text-lg">12.4 <span className="text-[10px]">MB/s</span></div>
                  </div>
                  <div className="bg-black/50 p-3 rounded border border-white/10">
                    <div className="opacity-50 mb-1 uppercase tracking-widest">Avg Latency</div>
                    <div className="text-[#00ff66] font-bold tracking-widest text-lg">4 <span className="text-[10px]">ms</span></div>
                  </div>
                </div>

                {selectedNode.status === 'threat' && (
                  <Button 
                    variant="danger" 
                    className="w-full h-10 font-bold tracking-widest shadow-[0_0_15px_rgba(255,42,85,0.4)] animate-pulse"
                    onClick={() => isolateThreat(selectedNode.id)}
                  >
                    ISOLATE NODE
                  </Button>
                )}
                {selectedNode.status === 'isolated' && (
                  <div className="py-2.5 px-3 bg-[#ffea00]/10 border border-[#ffea00]/30 text-[#ffea00] text-xs font-mono text-center rounded uppercase tracking-widest flex items-center justify-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    QUARANTINED
                  </div>
                )}
                {selectedNode.status === 'clean' && (
                  <div className="py-2.5 px-3 bg-[#00ff66]/10 border border-[#00ff66]/30 text-[#00ff66] text-xs font-mono text-center rounded uppercase tracking-widest flex items-center justify-center gap-2">
                    <Shield className="w-4 h-4" />
                    SECURE & ACTIVE
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-6 opacity-50">
                 <Network className="w-8 h-8 mx-auto mb-2 text-[#8a99af]" />
                 <p className="text-[10px] font-mono text-[#8a99af] uppercase tracking-widest">Select a node in the topography</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Terminal / Packet Feed */}
        <Card className="flex-1 bg-[#0a0d1a] border-[#00f5ff]/20 backdrop-blur-xl relative overflow-hidden min-h-[300px] shadow-[0_10px_30px_rgba(0,0,0,0.5)]">
          <CardContent className="p-4 h-full flex flex-col">
            <div className="flex items-center justify-between mb-4 border-b border-white/10 pb-2">
               <div className="flex items-center gap-2">
                 <div className="w-2 h-2 rounded-full bg-[#00f5ff] animate-pulse" />
                 <h3 className="text-[10px] font-mono tracking-[0.2em] font-bold uppercase text-white">Live Event Stream</h3>
               </div>
               <span className="text-[9px] font-mono text-[#8a99af]">PORT_LISTEN: 443</span>
            </div>
            
            <div className="flex-1 font-mono text-[10px] space-y-2 overflow-y-auto custom-scrollbar pr-2 pb-4">
              {log.map((entry, i) => (
                <div key={i} className={cn(
                   "flex gap-3 leading-relaxed", 
                   entry.type === 'crit' ? 'text-[#ff2a55] font-bold bg-[#ff2a55]/10 p-1.5 rounded -mx-1.5 px-1.5' : 
                   entry.type === 'warn' ? 'text-[#ffea00]' : 'text-[#8a99af]'
                )}>
                  <span className="opacity-60 whitespace-nowrap shrink-0">{entry.time}</span>
                  <span className="break-words">
                     {entry.type === 'crit' && <span className="font-bold mr-2">[ROOT_ALERT]</span>}
                     {entry.msg}
                  </span>
                </div>
              ))}
              {log.length === 0 && <p className="opacity-30 italic">AWAITING_TRAFFIC...</p>}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

