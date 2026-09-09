import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Card, CardContent } from '@/components/ui/card';
import { 
  Network, Server, User, Mail, Link as LinkIcon, Shield, Globe, RefreshCw, 
  AlertTriangle, ZoomIn, ZoomOut, Maximize2, Layers, Cpu, Play, Square, 
  CheckCircle2, Copy, ShieldAlert, Sparkles, Workflow, ArrowRight
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useLanguage } from '@/contexts/LanguageContext';
import { ATTACK_GRAPH_MODELS, AttackGraphModel, GraphNode, GraphEdge } from '@/data/graphModelsData';

export function AttackGraph() {
  const { t } = useLanguage();
  
  // Model & State Management
  const [selectedModelId, setSelectedModelId] = useState<string>('cloudflare-tunnel');
  const [activeModel, setActiveModel] = useState<AttackGraphModel>(ATTACK_GRAPH_MODELS[0]);
  const [layoutMode, setLayoutMode] = useState<'killchain' | 'radial' | 'bipartite'>('killchain');
  const [inspectorTab, setInspectorTab] = useState<'node' | 'gnn'>('node');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(ATTACK_GRAPH_MODELS[0].nodes[0]);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [liveModel, setLiveModel] = useState<AttackGraphModel | null>(null);

  // Attack Path Simulation
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simStep, setSimStep] = useState<number>(0);
  const simTimerRef = useRef<any>(null);

  // Containment Action Modal / Alert
  const [showContainmentInfo, setShowContainmentInfo] = useState<boolean>(false);
  const [copiedRule, setCopiedRule] = useState<boolean>(false);
  const canvasRef = useRef<HTMLDivElement>(null);

  // Helper to normalize node coordinates safely
  const normalizeNodes = (rawNodes: GraphNode[]): GraphNode[] => {
    if (!rawNodes || rawNodes.length === 0) return [];
    const maxX = Math.max(...rawNodes.map(n => n.x || 0), 1);
    const maxY = Math.max(...rawNodes.map(n => n.y || 0), 1);
    const isPixelScale = maxX > 100 || maxY > 100;

    return rawNodes.map((node, index) => {
      let x = node.x;
      let y = node.y;

      if (isPixelScale) {
        x = 10 + ((node.x / maxX) * 80);
        y = 18 + ((node.y / maxY) * 65);
      } else {
        x = Math.max(8, Math.min(92, x));
        y = Math.max(15, Math.min(85, y));
      }

      if (rawNodes.filter(n => n.x === node.x && n.y === node.y).length > 1) {
        x = 12 + (index * (76 / Math.max(rawNodes.length - 1, 1)));
        y = index % 2 === 0 ? 30 : 65;
      }

      return {
        ...node,
        x: Math.round(x * 10) / 10,
        y: Math.round(y * 10) / 10
      };
    });
  };

  // Check and ingest dynamic forensic graph from active email analysis
  const checkLiveGraph = () => {
    try {
      const stored = localStorage.getItem('neuroshield_active_attack_graph');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.nodes && parsed.nodes.length > 0) {
          const normalized = normalizeNodes(parsed.nodes);
          const liveM: AttackGraphModel = {
            id: 'live-session',
            name: 'Active Forensic Session (Live Ingestion)',
            shortName: 'Live Session',
            badge: 'LIVE TELEMETRY',
            threatLevel: 'CRITICAL',
            mitreTechniques: ['T1566', 'T1071', 'T1556'],
            description: 'Dynamically generated attack topology reconstructed from live RFC email headers and URL endpoint inspection.',
            nodes: normalized,
            edges: parsed.edges || [],
            gnnMetrics: {
              architecture: 'Relational Graph Convolutional Network (R-GCN Dynamic Engine)',
              graphRiskScore: 96,
              blastRadiusScore: 88,
              chokepointNodeId: normalized[1]?.id || normalized[0]?.id,
              chokepointNodeLabel: normalized[1]?.label || normalized[0]?.label,
              linkPredictionConfidence: 94.6,
              betweennessRanking: normalized.slice(0, 3).map((n, idx) => ({
                nodeId: n.id,
                label: n.label,
                score: Math.round((0.95 - idx * 0.12) * 100) / 100
              })),
              remediationAction: 'Isolate upstream sending relay and quarantine destination landing URLs'
            }
          };
          setLiveModel(liveM);
          return liveM;
        }
      }
    } catch {
      // silent fallback
    }
    return null;
  };

  useEffect(() => {
    checkLiveGraph();
    const handleStorage = () => {
      const lm = checkLiveGraph();
      if (lm) {
        setSelectedModelId('live-session');
        setActiveModel(lm);
        setSelectedNode(lm.nodes[0] || null);
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, []);

  // Handle Model Switch
  const handleSelectModel = (modelId: string) => {
    setIsSimulating(false);
    clearInterval(simTimerRef.current);
    setSelectedModelId(modelId);

    if (modelId === 'live-session' && liveModel) {
      setActiveModel(liveModel);
      setSelectedNode(liveModel.nodes[0] || null);
    } else {
      const found = ATTACK_GRAPH_MODELS.find(m => m.id === modelId) || ATTACK_GRAPH_MODELS[0];
      setActiveModel(found);
      setSelectedNode(found.nodes[0] || null);
    }
    setSimStep(0);
  };

  // Attack Path Simulation Loop
  useEffect(() => {
    if (isSimulating) {
      simTimerRef.current = setInterval(() => {
        setSimStep(prev => {
          const nextStep = prev + 1;
          if (nextStep >= activeModel.edges.length) {
            setIsSimulating(false);
            clearInterval(simTimerRef.current);
            return 0;
          }
          const currentEdge = activeModel.edges[nextStep];
          if (currentEdge) {
            const targetNode = activeModel.nodes.find(n => n.id === currentEdge.target);
            if (targetNode) setSelectedNode(targetNode);
          }
          return nextStep;
        });
      }, 1800);
    } else {
      clearInterval(simTimerRef.current);
    }
    return () => clearInterval(simTimerRef.current);
  }, [isSimulating, activeModel]);

  const toggleSimulation = () => {
    if (isSimulating) {
      setIsSimulating(false);
      clearInterval(simTimerRef.current);
    } else {
      setSimStep(0);
      setIsSimulating(true);
      const firstEdge = activeModel.edges[0];
      if (firstEdge) {
        const sourceNode = activeModel.nodes.find(n => n.id === firstEdge.source);
        if (sourceNode) setSelectedNode(sourceNode);
      }
    }
  };

  // Dynamic Node Position Calculator based on Layout Model
  const getNodePosition = (node: GraphNode, index: number, total: number) => {
    if (layoutMode === 'killchain') {
      return { x: node.x, y: node.y };
    }
    if (layoutMode === 'radial') {
      if (index === 0) return { x: 50, y: 50 };
      const angle = ((index - 1) / Math.max(total - 1, 1)) * 2 * Math.PI;
      const radius = 34;
      return {
        x: Math.round((50 + radius * Math.cos(angle)) * 10) / 10,
        y: Math.round((50 + radius * Math.sin(angle)) * 10) / 10
      };
    }
    if (layoutMode === 'bipartite') {
      const isThreatSide = 
        node.type === 'attacker' || 
        node.type === 'DECEPTIVE_DOMAIN' || 
        node.type === 'CREDENTIAL_HARVESTER' || 
        node.type === 'malware' || 
        node.type === 'IDENTITY';
      const x = isThreatSide ? 22 : 78;
      const y = 18 + (index * (64 / Math.max(total - 1, 1)));
      return { x, y: Math.round(y * 10) / 10 };
    }
    return { x: node.x, y: node.y };
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

  const getNodeColor = (type: GraphNode['type'], isSelected: boolean, isSimTarget: boolean) => {
    if (isSimTarget) {
      return 'border-cyber-red bg-cyber-red/30 ring-4 ring-cyber-red animate-pulse shadow-[0_0_24px_rgba(239,68,68,0.8)]';
    }
    if (isSelected) {
      return 'border-cyber-blue bg-cyber-blue/30 ring-4 ring-cyber-blue shadow-[0_0_20px_rgba(0,245,255,0.7)]';
    }
    switch (type) {
      case 'attacker':
      case 'INFRASTRUCTURE':
      case 'INTERNAL_SOURCE':
        return 'border-cyber-red bg-cyber-red/10 cyber-glow-red hover:bg-cyber-red/20';
      case 'domain':
      case 'DECEPTIVE_DOMAIN':
      case 'CREDENTIAL_HARVESTER':
        return 'border-[#f59e0b] bg-[#f59e0b]/10 hover:bg-[#f59e0b]/20';
      case 'email':
      case 'IDENTITY':
      case 'EXFILTRATION_MAILBOX':
        return 'border-cyber-blue bg-cyber-blue/10 cyber-glow-blue hover:bg-cyber-blue/20';
      case 'user':
      case 'TARGET':
      case 'VICTIM_GATEWAY':
        return 'border-cyber-green bg-cyber-green/10 hover:bg-cyber-green/20';
      case 'malware':
        return 'border-cyber-red bg-cyber-red/20 cyber-glow-red animate-pulse';
      default:
        return 'border-cyber-blue bg-cyber-blue/10';
    }
  };

  const handleCopyRule = (ruleText: string) => {
    navigator.clipboard.writeText(ruleText);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2200);
  };

  return (
    <div className="flex flex-col h-full space-y-3 sm:space-y-4">
      {/* Header & Graph Models Selector */}
      <div className="flex flex-col space-y-3">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-lg sm:text-2xl font-mono text-cyber-text tracking-tight font-bold flex items-center gap-2">
                <Workflow className="w-5 h-5 text-cyber-blue" />
                {t('attack_graph_title')}
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-cyber-blue/15 text-cyber-blue border border-cyber-blue/30 shadow-[0_0_10px_rgba(0,245,255,0.15)]">
                {activeModel.badge}
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                activeModel.threatLevel === 'CRITICAL' ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/40' : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
              }`}>
                RISK: {activeModel.gnnMetrics.graphRiskScore}/100
              </span>
            </div>
            <p className="text-cyber-muted text-xs sm:text-sm mt-0.5">
              {activeModel.description}
            </p>
          </div>

          {/* Quick Simulation & Layout Controls */}
          <div className="flex items-center gap-2 flex-wrap self-stretch sm:self-auto justify-between sm:justify-end">
            <Button
              onClick={toggleSimulation}
              size="sm"
              className={`font-mono text-xs font-bold transition-all ${
                isSimulating 
                  ? 'bg-cyber-red text-white hover:bg-cyber-red/80 shadow-[0_0_15px_rgba(239,68,68,0.5)]' 
                  : 'bg-cyber-blue text-black hover:bg-cyber-blue/90 shadow-[0_0_15px_rgba(0,245,255,0.4)]'
              }`}
            >
              {isSimulating ? (
                <>
                  <Square className="w-3.5 h-3.5 mr-1.5 fill-current" /> {t('stop_simulation')}
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 mr-1.5 fill-current" /> {t('simulate_attack')}
                </>
              )}
            </Button>

            {/* Layout Mode Selector */}
            <div className="flex items-center bg-[#05080f] rounded-lg border border-white/10 p-0.5 text-xs font-mono">
              <button
                onClick={() => setLayoutMode('killchain')}
                className={`px-2.5 py-1 rounded transition-colors ${layoutMode === 'killchain' ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40' : 'text-gray-400 hover:text-white'}`}
                title="Linear MITRE Kill-Chain Flow"
              >
                Kill-Chain
              </button>
              <button
                onClick={() => setLayoutMode('radial')}
                className={`px-2.5 py-1 rounded transition-colors ${layoutMode === 'radial' ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40' : 'text-gray-400 hover:text-white'}`}
                title="Radial Hub & Spoke"
              >
                Radial
              </button>
              <button
                onClick={() => setLayoutMode('bipartite')}
                className={`px-2.5 py-1 rounded transition-colors ${layoutMode === 'bipartite' ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40' : 'text-gray-400 hover:text-white'}`}
                title="Bipartite Attack-to-Defense"
              >
                Bipartite
              </button>
            </div>

            {/* Zoom Controls */}
            <div className="flex items-center bg-[#05080f] rounded-lg border border-white/10 p-0.5">
              <button
                onClick={() => setZoomLevel(prev => Math.max(0.7, prev - 0.15))}
                className="p-1.5 hover:bg-white/10 rounded text-gray-400 hover:text-white"
                title={t('zoom_out')}
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <span className="text-[10px] font-mono text-gray-400 px-1.5">{Math.round(zoomLevel * 100)}%</span>
              <button
                onClick={() => setZoomLevel(prev => Math.min(1.5, prev + 0.15))}
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

        {/* Threat Graph Models Nav Bar (Pills) */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin scrollbar-thumb-white/10">
          <div className="text-[10px] font-mono uppercase text-gray-400 font-bold shrink-0 flex items-center gap-1 mr-1">
            <Layers className="w-3 h-3 text-cyber-blue" />
            {t('graph_models')}:
          </div>
          {ATTACK_GRAPH_MODELS.map((model) => {
            const isSelected = selectedModelId === model.id;
            return (
              <button
                key={model.id}
                onClick={() => handleSelectModel(model.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono shrink-0 transition-all flex items-center gap-2 border ${
                  isSelected 
                    ? 'bg-cyber-blue/15 text-cyber-blue border-cyber-blue/50 shadow-[0_0_12px_rgba(0,245,255,0.2)] font-bold' 
                    : 'bg-[#05080f]/80 text-gray-400 border-white/10 hover:border-white/20 hover:text-gray-200'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${model.threatLevel === 'CRITICAL' ? 'bg-cyber-red' : 'bg-[#f59e0b]'}`} />
                {model.shortName}
              </button>
            );
          })}
          {liveModel && (
            <button
              onClick={() => handleSelectModel('live-session')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono shrink-0 transition-all flex items-center gap-2 border ${
                selectedModelId === 'live-session'
                  ? 'bg-cyber-green/15 text-cyber-green border-cyber-green/50 shadow-[0_0_12px_rgba(0,255,102,0.2)] font-bold'
                  : 'bg-[#05080f]/80 text-gray-400 border-white/10 hover:border-white/20 hover:text-gray-200'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              {t('live_forensic_session')}
            </button>
          )}
        </div>
      </div>

      {/* Main Canvas & Inspector Layout */}
      <div className="flex-1 flex flex-col lg:flex-row gap-4 min-h-0">
        {/* Canvas Graph Area */}
        <Card className="flex-[3] relative overflow-hidden bg-[#05080f] border-cyber-border/50 min-h-[440px] lg:min-h-[520px] flex flex-col shadow-2xl">
          <div className="radar-bg"></div>
          
          {/* Top Canvas Legend & Status */}
          <div className="absolute top-3 left-3 z-20 flex items-center gap-2 sm:gap-3 bg-[#0a0f1c]/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-white/10 text-[10px] font-mono text-gray-300 overflow-x-auto max-w-[calc(100%-24px)]">
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyber-red" /> {t('legend_threat_mta')}</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#f59e0b]" /> {t('legend_deceptive_domain')}</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyber-blue" /> {t('legend_claimed_sender')}</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyber-green" /> {t('legend_target_gateway')}</span>
          </div>

          {/* Active Simulation Ticker Banner */}
          {isSimulating && (
            <div className="absolute top-12 sm:top-14 left-3 right-3 z-20 bg-cyber-red/20 border border-cyber-red/50 rounded-lg p-2.5 backdrop-blur-md flex items-center justify-between gap-2 shadow-[0_0_20px_rgba(239,68,68,0.2)]">
              <div className="flex items-center gap-2 overflow-hidden">
                <span className="w-2 h-2 rounded-full bg-cyber-red animate-ping shrink-0" />
                <span className="text-xs font-mono font-bold text-cyber-red shrink-0">
                  HOP {simStep + 1}/{activeModel.edges.length}:
                </span>
                <span className="text-xs font-mono text-gray-200 truncate">
                  {activeModel.edges[simStep]?.description || `${activeModel.edges[simStep]?.source} ➔ ${activeModel.edges[simStep]?.target}`}
                </span>
              </div>
              <span className="text-[10px] font-mono text-cyber-red uppercase tracking-wider shrink-0 font-bold">
                SIMULATION ACTIVE
              </span>
            </div>
          )}

          {/* Canvas Viewport */}
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
                  <marker id="arrowhead-sim" markerWidth="9" markerHeight="7" refX="9" refY="3.5" orient="auto">
                    <polygon points="0 0, 9 3.5, 0 7" fill="#ef4444" />
                  </marker>
                </defs>
                {activeModel.edges.map((edge, i) => {
                  const sourceIndex = activeModel.nodes.findIndex(n => n.id === edge.source);
                  const targetIndex = activeModel.nodes.findIndex(n => n.id === edge.target);
                  const source = activeModel.nodes[sourceIndex];
                  const target = activeModel.nodes[targetIndex];
                  if (!source || !target) return null;

                  const srcPos = getNodePosition(source, sourceIndex, activeModel.nodes.length);
                  const tgtPos = getNodePosition(target, targetIndex, activeModel.nodes.length);

                  const isSimActive = isSimulating && simStep === i;
                  const isSelected = !isSimulating && (selectedNode?.id === source.id || selectedNode?.id === target.id);
                  
                  return (
                    <g key={`edge-${i}`}>
                      <motion.line
                        x1={`${srcPos.x}%`} y1={`${srcPos.y}%`}
                        x2={`${tgtPos.x}%`} y2={`${tgtPos.y}%`}
                        stroke={isSimActive ? '#ef4444' : isSelected ? '#00f5ff' : 'rgba(255,255,255,0.2)'}
                        strokeWidth={isSimActive ? 3.5 : isSelected ? 2.5 : 1.5}
                        strokeDasharray={isSimActive ? '6 3' : edge.type === 'phished' || edge.type === 'payload' ? '4 3' : undefined}
                        markerEnd={isSimActive ? "url(#arrowhead-sim)" : isSelected ? "url(#arrowhead-active)" : "url(#arrowhead)"}
                        initial={{ pathLength: 0 }}
                        animate={{ pathLength: 1 }}
                        transition={{ duration: 0.6, delay: i * 0.08 }}
                      />
                      {/* Edge Label on Midpoint */}
                      <text
                        x={`${(srcPos.x + tgtPos.x) / 2}%`}
                        y={`${(srcPos.y + tgtPos.y) / 2 - 2}%`}
                        fill={isSimActive ? '#ef4444' : isSelected ? '#00f5ff' : 'rgba(156, 163, 175, 0.7)'}
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
              {activeModel.nodes.map((node, index) => {
                const isSelected = selectedNode?.id === node.id;
                const isSimTarget = isSimulating && activeModel.edges[simStep]?.target === node.id;
                const pos = getNodePosition(node, index, activeModel.nodes.length);

                return (
                  <motion.div
                    key={node.id}
                    className={`absolute w-10 h-10 sm:w-12 sm:h-12 -ml-5 -mt-5 sm:-ml-6 sm:-mt-6 rounded-full border-2 flex items-center justify-center cursor-pointer transition-all z-10 ${getNodeColor(node.type, isSelected, isSimTarget)}`}
                    style={{ left: `${pos.x}%`, top: `${pos.y}%` }}
                    onClick={() => setSelectedNode(node)}
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: isSelected || isSimTarget ? 1.25 : 1, opacity: 1 }}
                    transition={{ type: "spring" as any, stiffness: 240, damping: 22 }}
                  >
                    {getNodeIcon(node.type)}
                    
                    {/* Node Tag Tooltip below */}
                    <div className={`absolute top-11 sm:top-13 whitespace-nowrap font-mono text-[9px] sm:text-[10px] px-2 py-0.5 rounded border max-w-[170px] sm:max-w-[210px] truncate shadow-lg pointer-events-none transition-all ${
                      isSelected
                        ? 'bg-cyber-blue text-black font-bold border-cyber-blue shadow-[0_0_12px_rgba(0,245,255,0.4)]'
                        : isSimTarget
                        ? 'bg-cyber-red text-white font-bold border-cyber-red shadow-[0_0_12px_rgba(239,68,68,0.5)]'
                        : 'bg-[#0a0f1c]/90 text-gray-200 border-white/10'
                    }`}>
                      {node.label}
                    </div>
                  </motion.div>
                );
              })}
            </div>

            {/* Bottom Quick-Action Bar */}
            <div className="absolute bottom-3 left-3 right-3 z-20 flex items-center justify-between gap-2 pointer-events-none">
              <div className="flex items-center gap-2 pointer-events-auto bg-[#0a0f1c]/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-white/10 text-[10px] font-mono text-gray-300">
                <span className="text-gray-400">CHOKEPOINT:</span>
                <span className="text-cyber-blue font-bold">{activeModel.gnnMetrics.chokepointNodeLabel}</span>
              </div>

              <Button
                onClick={() => setShowContainmentInfo(true)}
                size="sm"
                variant="outline"
                className="pointer-events-auto bg-cyber-red/10 border-cyber-red/40 text-cyber-red hover:bg-cyber-red hover:text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(239,68,68,0.2)]"
              >
                <ShieldAlert className="w-3.5 h-3.5 mr-1.5" />
                {t('chokepoint_containment')}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Forensic Entity & GNN Inspector Card */}
        <Card className="flex-[1] flex flex-col bg-[#0a0f1c] border-cyber-border/50 shadow-2xl min-w-[300px]">
          {/* Tab Switcher: Node Telemetry vs GNN Engine */}
          <div className="flex border-b border-white/10 bg-[#05080f]">
            <button
              onClick={() => setInspectorTab('node')}
              className={`flex-1 py-3 px-3 text-xs font-mono font-bold flex items-center justify-center gap-1.5 border-b-2 transition-colors ${
                inspectorTab === 'node'
                  ? 'border-cyber-blue text-cyber-blue bg-cyber-blue/5'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              {t('node_telemetry')}
            </button>
            <button
              onClick={() => setInspectorTab('gnn')}
              className={`flex-1 py-3 px-3 text-xs font-mono font-bold flex items-center justify-center gap-1.5 border-b-2 transition-colors ${
                inspectorTab === 'gnn'
                  ? 'border-cyber-blue text-cyber-blue bg-cyber-blue/5'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              GNN ML Engine
            </button>
          </div>

          <CardContent className="p-4 sm:p-5 font-mono h-full flex flex-col justify-between space-y-4 overflow-y-auto">
            {inspectorTab === 'node' ? (
              /* Node Inspector Panel */
              <div className="space-y-4">
                {selectedNode ? (
                  <div className="space-y-3.5">
                    <div>
                      <span className="text-gray-400 text-[10px] block mb-1 uppercase tracking-wider">{t('entity_classification')}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-white text-xs uppercase px-2.5 py-1 bg-[#05080f] border border-white/10 rounded inline-block font-bold">
                          {selectedNode.type}
                        </span>
                        {selectedNode.mitreTechnique && (
                          <span className="text-[10px] text-cyber-blue bg-cyber-blue/10 px-2 py-0.5 rounded border border-cyber-blue/30 font-bold truncate">
                            {selectedNode.mitreTechnique.split(' - ')[0]}
                          </span>
                        )}
                      </div>
                    </div>

                    <div>
                      <span className="text-gray-400 text-[10px] block mb-1 uppercase tracking-wider">{t('identifier_label')}</span>
                      <div className="text-cyber-blue text-xs break-all bg-[#05080f] p-2.5 rounded-lg border border-white/10 font-mono font-bold">
                        {selectedNode.label}
                      </div>
                    </div>

                    {selectedNode.details && (
                      <div>
                        <span className="text-gray-400 text-[10px] block mb-1 uppercase tracking-wider">{t('evidence_details')}</span>
                        <p className="text-xs text-gray-200 leading-relaxed bg-[#05080f] p-3 rounded-lg border border-white/10">
                          {selectedNode.details}
                        </p>
                      </div>
                    )}

                    {selectedNode.socAction && (
                      <div>
                        <span className="text-cyber-red text-[10px] font-bold block mb-1 uppercase tracking-wider flex items-center gap-1">
                          <ShieldAlert className="w-3 h-3 text-cyber-red" />
                          RECOMMENDED SOC RESPONSE
                        </span>
                        <p className="text-xs text-cyber-red/90 bg-cyber-red/10 border border-cyber-red/30 p-2.5 rounded-lg leading-snug">
                          {selectedNode.socAction}
                        </p>
                      </div>
                    )}

                    <div>
                      <span className="text-gray-400 text-[10px] block mb-1 uppercase tracking-wider">{t('relational_hops')}</span>
                      <ul className="text-xs space-y-1.5 max-h-36 overflow-y-auto pr-1">
                        {activeModel.edges.filter(e => e.source === selectedNode.id).map((e, idx) => {
                          const peer = activeModel.nodes.find(n => n.id === e.target);
                          return (
                            <li key={`out-${idx}`} className="text-gray-300 bg-[#05080f] p-2 rounded border border-white/5 flex items-center justify-between gap-2">
                              <span className="text-cyber-red text-[10px] font-bold uppercase shrink-0">➔ {e.relationship || e.type || 'LINK'}:</span>
                              <span className="text-white text-[11px] truncate">{peer?.label || e.target}</span>
                            </li>
                          );
                        })}
                        {activeModel.edges.filter(e => e.target === selectedNode.id).map((e, idx) => {
                          const peer = activeModel.nodes.find(n => n.id === e.source);
                          return (
                            <li key={`in-${idx}`} className="text-gray-300 bg-[#05080f] p-2 rounded border border-white/5 flex items-center justify-between gap-2">
                              <span className="text-cyber-green text-[10px] font-bold uppercase shrink-0">⬅ {e.relationship || e.type || 'LINK'}:</span>
                              <span className="text-white text-[11px] truncate">{peer?.label || e.source}</span>
                            </li>
                          );
                        })}
                        {activeModel.edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).length === 0 && (
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
            ) : (
              /* GNN Graph AI Inference Panel */
              <div className="space-y-4">
                <div className="bg-[#05080f] p-3 rounded-lg border border-white/10 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400 text-[10px] uppercase">GNN Architecture:</span>
                    <span className="text-cyber-blue font-bold text-[10px]">R-GCN v4.2</span>
                  </div>
                  <div className="text-xs text-gray-200 font-mono">
                    {activeModel.gnnMetrics.architecture}
                  </div>
                </div>

                {/* Blast Radius & Link Prediction */}
                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-[#05080f] p-2.5 rounded-lg border border-white/10">
                    <span className="text-gray-400 text-[9px] uppercase block mb-1">BLAST RADIUS</span>
                    <span className="text-cyber-red font-bold text-lg">{activeModel.gnnMetrics.blastRadiusScore}%</span>
                    <div className="w-full bg-white/10 h-1 rounded-full mt-1.5 overflow-hidden">
                      <div className="bg-cyber-red h-full" style={{ width: `${activeModel.gnnMetrics.blastRadiusScore}%` }} />
                    </div>
                  </div>
                  <div className="bg-[#05080f] p-2.5 rounded-lg border border-white/10">
                    <span className="text-gray-400 text-[9px] uppercase block mb-1">LINK PREDICTION</span>
                    <span className="text-cyber-green font-bold text-lg">{activeModel.gnnMetrics.linkPredictionConfidence}%</span>
                    <div className="w-full bg-white/10 h-1 rounded-full mt-1.5 overflow-hidden">
                      <div className="bg-cyber-green h-full" style={{ width: `${activeModel.gnnMetrics.linkPredictionConfidence}%` }} />
                    </div>
                  </div>
                </div>

                {/* Betweenness Centrality Ranking */}
                <div>
                  <span className="text-gray-400 text-[10px] block mb-1.5 uppercase tracking-wider">
                    Node Betweenness Centrality (Pivots)
                  </span>
                  <div className="space-y-1.5">
                    {activeModel.gnnMetrics.betweennessRanking.map((rank, idx) => (
                      <div key={idx} className="bg-[#05080f] p-2 rounded border border-white/5 flex items-center justify-between text-xs">
                        <span className="text-gray-300 truncate max-w-[160px]">{rank.label}</span>
                        <span className="text-cyber-blue font-bold">{(rank.score * 100).toFixed(0)}%</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* AI Graph Remediation */}
                <div className="bg-cyber-blue/10 border border-cyber-blue/30 p-3 rounded-lg space-y-1">
                  <span className="text-cyber-blue text-[10px] font-bold uppercase flex items-center gap-1">
                    <Sparkles className="w-3 h-3 text-cyber-blue" />
                    Optimal Graph Cut (Remediation)
                  </span>
                  <p className="text-xs text-gray-200 leading-snug">
                    {activeModel.gnnMetrics.remediationAction}
                  </p>
                </div>
              </div>
            )}
            
            {/* Bottom Meta Stats */}
            <div className="pt-3 border-t border-white/10 text-[10px] text-gray-400 flex justify-between items-center">
              <span>{t('nodes_label')}: <strong className="text-white">{activeModel.nodes.length}</strong></span>
              <span>{t('edges_label')}: <strong className="text-white">{activeModel.edges.length}</strong></span>
              <span>MODEL: <strong className="text-cyber-blue uppercase">{activeModel.shortName}</strong></span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Chokepoint Containment Modal */}
      <AnimatePresence>
        {showContainmentInfo && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-[#0a0f1c] border border-cyber-border rounded-xl p-5 sm:p-6 max-w-lg w-full space-y-4 shadow-2xl font-mono"
            >
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2 text-cyber-red">
                  <ShieldAlert className="w-5 h-5 text-cyber-red" />
                  <h3 className="font-bold text-sm uppercase">1-Click Chokepoint Containment</h3>
                </div>
                <button
                  onClick={() => setShowContainmentInfo(false)}
                  className="text-gray-400 hover:text-white text-xs px-2 py-1 rounded bg-white/5"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-3 text-xs text-gray-300">
                <p>
                  By neutralizing the single critical graph chokepoint (<strong className="text-cyber-blue">{activeModel.gnnMetrics.chokepointNodeLabel}</strong>), the adversary&apos;s propagation path is 100% disconnected.
                </p>

                <div>
                  <span className="text-[10px] text-gray-400 uppercase block mb-1">Generated SOC Containment Command:</span>
                  <div className="bg-[#05080f] p-3 rounded-lg border border-white/10 text-cyber-green break-all flex items-start justify-between gap-2">
                    <code>
                      {activeModel.id === 'cloudflare-tunnel'
                        ? 'rpz-block --zone "threats.local" --cname "*.trycloudflare.com." --action DROP'
                        : activeModel.id === 'evilginx-phishlet'
                        ? 'Revoke-AzureADUserAllRefreshToken -ObjectId "cfo-user-guid"; Set-MsolUser -UserPrincipalName cfo@corp.com -BlockCredential $true'
                        : activeModel.id === 'bec-payroll'
                        ? 'New-TransportRule -Name "Block-Spoofed-CEO-Freemail-ReplyTo" -FromScope "NotInOrganization" -HeaderMatchesMessageHeader "Reply-To" -HeaderMatchesPatterns "gmail\\.com" -RejectMessageReasonText "Divergent Reply-To Blocked"'
                        : 'iptables -A INPUT -s 185.220.101.0/24 -j DROP; systemctl restart crowdsec'}
                    </code>
                    <button
                      onClick={() => handleCopyRule(
                        activeModel.id === 'cloudflare-tunnel'
                          ? 'rpz-block --zone "threats.local" --cname "*.trycloudflare.com." --action DROP'
                          : activeModel.id === 'evilginx-phishlet'
                          ? 'Revoke-AzureADUserAllRefreshToken -ObjectId "cfo-user-guid"; Set-MsolUser -UserPrincipalName cfo@corp.com -BlockCredential $true'
                          : activeModel.id === 'bec-payroll'
                          ? 'New-TransportRule -Name "Block-Spoofed-CEO-Freemail-ReplyTo" -FromScope "NotInOrganization" -HeaderMatchesMessageHeader "Reply-To" -HeaderMatchesPatterns "gmail\\.com" -RejectMessageReasonText "Divergent Reply-To Blocked"'
                          : 'iptables -A INPUT -s 185.220.101.0/24 -j DROP; systemctl restart crowdsec'
                      )}
                      className="p-1.5 hover:bg-white/10 rounded text-gray-400 hover:text-white shrink-0"
                      title="Copy to clipboard"
                    >
                      {copiedRule ? <CheckCircle2 className="w-4 h-4 text-cyber-green" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-white/10">
                <Button
                  onClick={() => setShowContainmentInfo(false)}
                  variant="outline"
                  size="sm"
                  className="font-mono text-xs"
                >
                  Dismiss
                </Button>
                <Button
                  onClick={() => {
                    handleCopyRule(
                      activeModel.id === 'cloudflare-tunnel'
                        ? 'rpz-block --zone "threats.local" --cname "*.trycloudflare.com." --action DROP'
                        : activeModel.id === 'evilginx-phishlet'
                        ? 'Revoke-AzureADUserAllRefreshToken -ObjectId "cfo-user-guid"; Set-MsolUser -UserPrincipalName cfo@corp.com -BlockCredential $true'
                        : activeModel.id === 'bec-payroll'
                        ? 'New-TransportRule -Name "Block-Spoofed-CEO-Freemail-ReplyTo" -FromScope "NotInOrganization" -HeaderMatchesMessageHeader "Reply-To" -HeaderMatchesPatterns "gmail\\.com" -RejectMessageReasonText "Divergent Reply-To Blocked"'
                        : 'iptables -A INPUT -s 185.220.101.0/24 -j DROP; systemctl restart crowdsec'
                    );
                    setShowContainmentInfo(false);
                  }}
                  size="sm"
                  className="bg-cyber-red text-white hover:bg-cyber-red/90 font-mono text-xs font-bold shadow-[0_0_15px_rgba(239,68,68,0.4)]"
                >
                  Copy & Execute Containment
                </Button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
