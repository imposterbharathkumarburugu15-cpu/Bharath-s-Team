import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { 
  Globe, 
  MapPin, 
  Crosshair, 
  RotateCw, 
  Layers, 
  Maximize2, 
  Minimize2, 
  Play, 
  Pause, 
  Compass, 
  Radio, 
  Navigation, 
  ShieldAlert, 
  Server,
  Zap,
  Info,
  ExternalLink,
  Search,
  CheckCircle2,
  RefreshCw,
  Clock
} from 'lucide-react';
import { OriginIPIntel, HeaderHop, fetchLiveIPIntelligence } from '../services/forensicsEngine';
import { GoogleMapsTacticalRadar } from './GoogleMapsTacticalRadar';

interface Forensic3DGeoMapProps {
  originIP: OriginIPIntel;
  hops?: HeaderHop[];
  targetLocation?: { lat: number; lng: number; label: string };
  isCompact?: boolean;
}

// Major World Continents Coordinate Outlines for 3D Cyber Globe Rendering
const CONTINENT_POLYGONS: [number, number][][] = [
  // North America
  [[60, -140], [70, -160], [72, -130], [60, -70], [45, -60], [30, -80], [20, -100], [15, -90], [10, -80], [15, -105], [30, -120], [50, -130], [60, -140]],
  // South America
  [[10, -75], [5, -50], [-10, -35], [-25, -45], [-45, -65], [-55, -70], [-35, -75], [-15, -75], [0, -80], [10, -75]],
  // Europe
  [[35, -10], [45, -10], [55, 5], [60, 5], [70, 25], [60, 40], [50, 40], [40, 30], [35, 25], [35, -10]],
  // Africa
  [[35, -5], [35, 30], [15, 45], [0, 40], [-15, 40], [-35, 20], [-35, 15], [0, 10], [15, -15], [30, -10], [35, -5]],
  // Asia
  [[40, 30], [55, 40], [70, 70], [70, 140], [60, 170], [40, 140], [30, 120], [10, 100], [10, 80], [25, 60], [40, 30]],
  // Australia
  [[-15, 130], [-12, 140], [-25, 150], [-38, 145], [-35, 115], [-20, 115], [-15, 130]],
  // Greenland
  [[60, -45], [75, -20], [82, -30], [75, -60], [60, -45]],
  // UK & Ireland
  [[50, -5], [58, -3], [58, -8], [50, -5]],
  // Japan
  [[32, 130], [42, 142], [45, 142], [35, 135], [32, 130]]
];

export const Forensic3DGeoMap: React.FC<Forensic3DGeoMapProps> = ({
  originIP,
  hops = [],
  targetLocation = { lat: 37.7749, lng: -122.4194, label: 'Target Mail Gateway' },
  isCompact = false
}) => {
  const [activeIntel, setActiveIntel] = useState<OriginIPIntel>(originIP);
  const [searchTarget, setSearchTarget] = useState<string>('');
  const [isResolving, setIsResolving] = useState<boolean>(false);
  const [showSearch, setShowSearch] = useState<boolean>(false);

  const [viewMode, setViewMode] = useState<'3d-globe' | 'tactical-map' | 'transit-trail'>('3d-globe');
  const [isAutoRotating, setIsAutoRotating] = useState<boolean>(true);
  const [isExpanded, setIsExpanded] = useState<boolean>(false);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [activeHopIndex, setActiveHopIndex] = useState<number>(0);
  const [isPlayingTrail, setIsPlayingTrail] = useState<boolean>(false);
  const [cursorCoords, setCursorCoords] = useState<{ lat: number; lng: number } | null>(null);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const animationFrameRef = useRef<number | null>(null);

  // Sync with prop when prop changes
  useEffect(() => {
    setActiveIntel(originIP);
  }, [originIP]);

  // Coordinates
  const originLat = activeIntel.latitude ?? 37.7749;
  const originLng = activeIntel.longitude ?? -122.4194;

  // 3D Globe Spherical Angles (in radians)
  const rotationYRef = useRef<number>(((-originLng || 0) * Math.PI) / 180);
  const rotationXRef = useRef<number>(((originLat || 30) * Math.PI) / 180 * 0.4);
  const targetRotationYRef = useRef<number>(((-originLng || 0) * Math.PI) / 180);
  const targetRotationXRef = useRef<number>(((originLat || 30) * Math.PI) / 180 * 0.4);
  const isDraggingRef = useRef<boolean>(false);
  const lastMousePosRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  const googleMapsApiKey = (import.meta as any).env?.VITE_GOOGLE_MAPS_API_KEY || '';

  // Format Geohash & Coordinates Display
  const formattedCoords = useMemo(() => {
    const latDir = originLat >= 0 ? 'N' : 'S';
    const lngDir = originLng >= 0 ? 'E' : 'W';
    return {
      lat: `${Math.abs(originLat).toFixed(4)}° ${latDir}`,
      lng: `${Math.abs(originLng).toFixed(4)}° ${lngDir}`,
      dms: `${Math.floor(Math.abs(originLat))}° ${Math.floor((Math.abs(originLat) % 1) * 60)}' ${latDir}, ${Math.floor(Math.abs(originLng))}° ${Math.floor((Math.abs(originLng) % 1) * 60)}' ${lngDir}`
    };
  }, [originLat, originLng]);

  // Smooth Lock-On to Origin Coordinates
  const handleLockOnTarget = useCallback(() => {
    setIsAutoRotating(false);
    targetRotationYRef.current = ((-originLng * Math.PI) / 180) + Math.PI / 2;
    targetRotationXRef.current = (originLat * Math.PI) / 180 * 0.5;
  }, [originLat, originLng]);

  // Trigger lock-on whenever coordinates change
  useEffect(() => {
    targetRotationYRef.current = ((-originLng * Math.PI) / 180) + Math.PI / 2;
    targetRotationXRef.current = (originLat * Math.PI) / 180 * 0.5;
  }, [originLat, originLng]);

  // Handle Real-Time Live Geo Query
  const handlePerformLiveQuery = async (targetToQuery?: string) => {
    const query = (targetToQuery || searchTarget).trim();
    if (!query) return;
    setIsResolving(true);
    try {
      const result = await fetchLiveIPIntelligence(query);
      setActiveIntel(result);
      setIsAutoRotating(false);
      targetRotationYRef.current = (((-(result.longitude || 0)) * Math.PI) / 180) + Math.PI / 2;
      targetRotationXRef.current = ((result.latitude || 0) * Math.PI) / 180 * 0.5;
    } catch (e) {
      console.error('Failed to resolve live IP:', e);
    } finally {
      setIsResolving(false);
    }
  };

  // Handle Mouse/Touch Interaction for 3D Globe
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    isDraggingRef.current = true;
    setIsAutoRotating(false);
    lastMousePosRef.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!isDraggingRef.current) return;
    const deltaX = e.clientX - lastMousePosRef.current.x;
    const deltaY = e.clientY - lastMousePosRef.current.y;
    lastMousePosRef.current = { x: e.clientX, y: e.clientY };

    rotationYRef.current += deltaX * 0.006;
    rotationXRef.current = Math.max(-1.2, Math.min(1.2, rotationXRef.current - deltaY * 0.006));
    targetRotationYRef.current = rotationYRef.current;
    targetRotationXRef.current = rotationXRef.current;
  };

  const handleMouseUp = () => {
    isDraggingRef.current = false;
  };

  const handleTouchStart = (e: React.TouchEvent<HTMLCanvasElement>) => {
    if (e.touches.length === 1) {
      isDraggingRef.current = true;
      setIsAutoRotating(false);
      lastMousePosRef.current = { x: e.touches[0].clientX, y: e.touches[0].clientY };
    }
  };

  const handleTouchMove = (e: React.TouchEvent<HTMLCanvasElement>) => {
    if (!isDraggingRef.current || e.touches.length !== 1) return;
    const deltaX = e.touches[0].clientX - lastMousePosRef.current.x;
    const deltaY = e.touches[0].clientY - lastMousePosRef.current.y;
    lastMousePosRef.current = { x: e.touches[0].clientX, y: e.touches[0].clientY };

    rotationYRef.current += deltaX * 0.008;
    rotationXRef.current = Math.max(-1.2, Math.min(1.2, rotationXRef.current - deltaY * 0.008));
    targetRotationYRef.current = rotationYRef.current;
    targetRotationXRef.current = rotationXRef.current;
  };

  // Trajectory Hops Builder
  const transitNodes = useMemo(() => {
    const nodes = [
      {
        name: `Origin Node (${activeIntel.city || 'Origin'})`,
        ip: activeIntel.ip,
        lat: originLat,
        lng: originLng,
        type: 'ORIGIN'
      }
    ];

    if (hops && hops.length > 0) {
      hops.forEach((h, idx) => {
        const fraction = (idx + 1) / (hops.length + 1);
        const midLat = h.latitude ?? (originLat + (targetLocation.lat - originLat) * fraction + (idx % 2 === 0 ? 5 : -5));
        const midLng = h.longitude ?? (originLng + (targetLocation.lng - originLng) * fraction);
        nodes.push({
          name: `Relay Hop #${h.hopNumber}: ${h.sourceHostname || h.sourceIP}`,
          ip: h.sourceIP,
          lat: midLat,
          lng: midLng,
          type: 'RELAY'
        });
      });
    }

    nodes.push({
      name: `Target Gateway (${targetLocation.label})`,
      ip: '104.244.42.1',
      lat: targetLocation.lat,
      lng: targetLocation.lng,
      type: 'TARGET'
    });

    return nodes;
  }, [originLat, originLng, activeIntel, hops, targetLocation]);

  // 3D Canvas Ray-Casting & Orthographic Spherical Projection Engine
  useEffect(() => {
    if (viewMode !== '3d-globe') return;

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let isRunning = true;
    let pulsePhase = 0;

    const project3D = (lat: number, lng: number, radius: number, rotX: number, rotY: number) => {
      const phi = (90 - lat) * (Math.PI / 180);
      const theta = (lng + 180) * (Math.PI / 180);

      const x0 = -(radius * Math.sin(phi) * Math.cos(theta));
      const z0 = radius * Math.sin(phi) * Math.sin(theta);
      const y0 = radius * Math.cos(phi);

      const x1 = x0 * Math.cos(rotY) + z0 * Math.sin(rotY);
      const z1 = -x0 * Math.sin(rotY) + z0 * Math.cos(rotY);
      const y1 = y0;

      const y2 = y1 * Math.cos(rotX) - z1 * Math.sin(rotX);
      const z2 = y1 * Math.sin(rotX) + z1 * Math.cos(rotX);
      const x2 = x1;

      return {
        x: x2,
        y: -y2,
        z: z2,
        visible: z2 > -radius * 0.15
      };
    };

    const render = () => {
      if (!isRunning) return;

      const rect = canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) {
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
      }

      ctx.save();
      ctx.scale(dpr, dpr);
      const width = rect.width;
      const height = rect.height;

      ctx.clearRect(0, 0, width, height);

      // Auto rotation dampening
      if (isAutoRotating) {
        targetRotationYRef.current += 0.003;
      }
      rotationYRef.current += (targetRotationYRef.current - rotationYRef.current) * 0.08;
      rotationXRef.current += (targetRotationXRef.current - rotationXRef.current) * 0.08;

      const centerX = width / 2;
      const centerY = height / 2;
      const baseRadius = Math.min(width, height) * 0.38;
      const radius = baseRadius * zoomLevel;

      pulsePhase = (pulsePhase + 0.04) % (Math.PI * 2);

      // 1. Globe Ambient Background & Glow
      const bgGrad = ctx.createRadialGradient(centerX, centerY, radius * 0.4, centerX, centerY, radius * 1.3);
      bgGrad.addColorStop(0, 'rgba(10, 25, 50, 0.9)');
      bgGrad.addColorStop(0.7, 'rgba(5, 12, 28, 0.95)');
      bgGrad.addColorStop(1, 'rgba(2, 6, 15, 0.4)');
      ctx.fillStyle = bgGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.fill();

      // Atmospheric Rim Glow
      ctx.strokeStyle = 'rgba(0, 245, 255, 0.35)';
      ctx.lineWidth = 2;
      ctx.stroke();

      // 2. Render Lat/Lng Cyber Grids
      ctx.lineWidth = 0.5;
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.strokeStyle = 'rgba(0, 245, 255, 0.12)';
        ctx.beginPath();
        let first = true;
        for (let lng = -180; lng <= 180; lng += 10) {
          const pt = project3D(lat, lng, radius, rotationXRef.current, rotationYRef.current);
          if (pt.visible) {
            if (first) {
              ctx.moveTo(centerX + pt.x, centerY + pt.y);
              first = false;
            } else {
              ctx.lineTo(centerX + pt.x, centerY + pt.y);
            }
          } else {
            first = true;
          }
        }
        ctx.stroke();
      }

      for (let lng = -180; lng < 180; lng += 45) {
        ctx.strokeStyle = 'rgba(0, 245, 255, 0.12)';
        ctx.beginPath();
        let first = true;
        for (let lat = -85; lat <= 85; lat += 5) {
          const pt = project3D(lat, lng, radius, rotationXRef.current, rotationYRef.current);
          if (pt.visible) {
            if (first) {
              ctx.moveTo(centerX + pt.x, centerY + pt.y);
              first = false;
            } else {
              ctx.lineTo(centerX + pt.x, centerY + pt.y);
            }
          } else {
            first = true;
          }
        }
        ctx.stroke();
      }

      // 3. Render Landmass Outlines & Fill
      ctx.fillStyle = 'rgba(0, 245, 255, 0.08)';
      ctx.strokeStyle = 'rgba(0, 245, 255, 0.45)';
      ctx.lineWidth = 1.2;

      CONTINENT_POLYGONS.forEach((poly) => {
        ctx.beginPath();
        let visibleCount = 0;
        poly.forEach(([lat, lng], idx) => {
          const pt = project3D(lat, lng, radius, rotationXRef.current, rotationYRef.current);
          if (pt.visible) visibleCount++;
          const sx = centerX + pt.x;
          const sy = centerY + pt.y;
          if (idx === 0) ctx.moveTo(sx, sy);
          else ctx.lineTo(sx, sy);
        });
        ctx.closePath();
        if (visibleCount > poly.length * 0.3) {
          ctx.fill();
          ctx.stroke();
        }
      });

      // 4. Render Transit Trajectory Arc (Origin -> Target)
      const originPt = project3D(originLat, originLng, radius, rotationXRef.current, rotationYRef.current);
      const targetPt = project3D(targetLocation.lat, targetLocation.lng, radius, rotationXRef.current, rotationYRef.current);

      if (originPt.visible || targetPt.visible) {
        ctx.beginPath();
        const arcSteps = 30;
        let arcFirst = true;

        for (let i = 0; i <= arcSteps; i++) {
          const t = i / arcSteps;
          const curLat = originLat + (targetLocation.lat - originLat) * t;
          const curLng = originLng + (targetLocation.lng - originLng) * t;
          const altitude = Math.sin(t * Math.PI) * (radius * 0.18);
          const pt = project3D(curLat, curLng, radius + altitude, rotationXRef.current, rotationYRef.current);

          if (pt.visible) {
            if (arcFirst) {
              ctx.moveTo(centerX + pt.x, centerY + pt.y);
              arcFirst = false;
            } else {
              ctx.lineTo(centerX + pt.x, centerY + pt.y);
            }
          }
        }

        ctx.strokeStyle = 'rgba(255, 59, 48, 0.7)';
        ctx.lineWidth = 2;
        ctx.setLineDash([4, 4]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      // 5. Render Origin Node (Attacker / Sending Mail Server)
      if (originPt.visible) {
        const ox = centerX + originPt.x;
        const oy = centerY + originPt.y;

        const pulseRadius = 6 + Math.sin(pulsePhase) * 6;
        ctx.fillStyle = 'rgba(239, 68, 68, 0.35)';
        ctx.beginPath();
        ctx.arc(ox, oy, pulseRadius, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#ef4444';
        ctx.beginPath();
        ctx.arc(ox, oy, 4, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(ox, oy, 4, 0, Math.PI * 2);
        ctx.stroke();

        // Node Label HUD Tag
        if (originPt.z > -radius * 0.05) {
          const tagX = ox + 12;
          const tagY = oy - 22;

          ctx.fillStyle = 'rgba(8, 14, 28, 0.9)';
          ctx.strokeStyle = 'rgba(239, 68, 68, 0.8)';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.roundRect(tagX, tagY, 150, 36, 4);
          ctx.fill();
          ctx.stroke();

          ctx.fillStyle = '#ef4444';
          ctx.font = 'bold 8.5px "JetBrains Mono", monospace';
          ctx.fillText(`TARGET: ${activeIntel.ip.slice(0, 16)}`, tagX + 6, tagY + 12);
          ctx.fillStyle = '#38bdf8';
          ctx.font = '7.5px "JetBrains Mono", monospace';
          ctx.fillText(`${activeIntel.city || 'City'}, ${activeIntel.countryCode || activeIntel.country || 'Region'}`, tagX + 6, tagY + 22);
          ctx.fillStyle = '#94a3b8';
          ctx.font = '7px "JetBrains Mono", monospace';
          ctx.fillText(`${activeIntel.asn || 'AS-TRANSIT'}`, tagX + 6, tagY + 31);
        }
      }

      // 6. Render Target Node
      if (targetPt.visible) {
        const tx = centerX + targetPt.x;
        const ty = centerY + targetPt.y;

        ctx.fillStyle = '#10b981';
        ctx.beginPath();
        ctx.arc(tx, ty, 3.5, 0, Math.PI * 2);
        ctx.fill();
      }

      // 7. Outer Compass Ring
      ctx.strokeStyle = 'rgba(0, 245, 255, 0.15)';
      ctx.lineWidth = 1;
      ctx.setLineDash([2, 6]);
      ctx.beginPath();
      ctx.ellipse(centerX, centerY, radius * 1.25, radius * 0.4, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.restore();

      animationFrameRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      isRunning = false;
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current);
    };
  }, [viewMode, originLat, originLng, targetLocation, activeIntel, isAutoRotating, zoomLevel]);

  return (
    <div className={`relative bg-[#070c18] border border-white/10 rounded-2xl overflow-hidden shadow-2xl transition-all ${
      isExpanded ? 'fixed inset-4 z-50 flex flex-col' : 'w-full'
    }`}>
      {/* Top Cyber HUD Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 bg-[#0a1224]/90 border-b border-white/10 backdrop-blur-md">
        <div className="flex items-center gap-2.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-white font-mono uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-cyber-blue" />
                GEOSPATIAL FORENSIC 3D RADAR
              </span>
              <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded uppercase border flex items-center gap-1 ${
                activeIntel.lookupStatus === 'RESOLVED'
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                  : activeIntel.lookupStatus === 'PRIVATE_IP'
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
              }`}>
                <CheckCircle2 className="w-2.5 h-2.5" />
                {activeIntel.lookupStatus === 'RESOLVED' ? 'LIVE TELEMETRY' : activeIntel.lookupStatus === 'PRIVATE_IP' ? 'RFC1918 PRIVATE' : 'APPROX REGIONAL'}
              </span>
            </div>
            <span className="text-[10px] text-gray-300 font-mono flex items-center gap-1.5 mt-0.5">
              <span className="text-white font-bold">{activeIntel.city || 'Autonomous City'}, {activeIntel.region || ''} {activeIntel.country || 'Public Zone'}</span>
              <span className="text-gray-500">•</span>
              <span className="text-cyber-blue font-bold">{formattedCoords.lat}, {formattedCoords.lng}</span>
              {activeIntel.timezone && (
                <>
                  <span className="text-gray-500">•</span>
                  <span className="text-gray-400 flex items-center gap-1"><Clock className="w-2.5 h-2.5 text-gray-400" />{activeIntel.timezone}</span>
                </>
              )}
            </span>
          </div>
        </div>

        {/* View Mode Switcher & Live Lookup Toggle */}
        <div className="flex items-center gap-1 bg-[#05080f] p-1 rounded-xl border border-white/10">
          <button
            onClick={() => setShowSearch(!showSearch)}
            title="Inspect / Geoplot custom IP or Domain"
            className={`px-2 py-1 rounded-lg text-[11px] font-mono font-bold transition-all flex items-center gap-1 ${
              showSearch ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'text-gray-400 hover:text-white'
            }`}
          >
            <Search className="w-3 h-3" />
            <span className="hidden sm:inline">IP / Host Query</span>
          </button>

          <button
            onClick={() => setViewMode('3d-globe')}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold transition-all flex items-center gap-1.5 ${
              viewMode === '3d-globe' 
                ? 'bg-cyber-blue text-black shadow-md' 
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Globe className="w-3 h-3" />
            <span>3D Cyber Globe</span>
          </button>

          <button
            onClick={() => setViewMode('tactical-map')}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold transition-all flex items-center gap-1.5 ${
              viewMode === 'tactical-map' 
                ? 'bg-cyber-blue text-black shadow-md' 
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Layers className="w-3 h-3" />
            <span>Google Maps™ Radar</span>
          </button>

          <button
            onClick={() => setViewMode('transit-trail')}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold transition-all flex items-center gap-1.5 ${
              viewMode === 'transit-trail' 
                ? 'bg-cyber-blue text-black shadow-md' 
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Navigation className="w-3 h-3" />
            <span>Transit Hops</span>
          </button>

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            title={isExpanded ? 'Exit Full Screen' : 'Expand Full Screen'}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-colors ml-1"
          >
            {isExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Live Target IP / Domain Inspector Bar */}
      {showSearch && (
        <div className="bg-[#05080f] px-4 py-2.5 border-b border-white/10 flex flex-wrap items-center gap-2 text-xs font-mono">
          <span className="text-gray-400 font-bold flex items-center gap-1">
            <Radio className="w-3.5 h-3.5 text-cyber-blue" />
            LIVE GEO QUERY:
          </span>
          <div className="flex-1 min-w-[200px] flex items-center gap-2">
            <input
              type="text"
              value={searchTarget}
              onChange={(e) => setSearchTarget(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handlePerformLiveQuery()}
              placeholder="e.g. 104.28.19.44, trycloudflare.com, 185.220.101.45"
              className="flex-1 bg-[#0a1224] border border-white/15 rounded-lg px-3 py-1.5 text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue font-mono text-xs"
            />
            <button
              onClick={() => handlePerformLiveQuery()}
              disabled={isResolving || !searchTarget.trim()}
              className="px-3 py-1.5 bg-cyber-blue text-black font-bold rounded-lg hover:bg-cyan-300 disabled:opacity-50 transition-all flex items-center gap-1.5"
            >
              {isResolving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Crosshair className="w-3.5 h-3.5" />}
              <span>{isResolving ? 'Locating...' : 'Locate'}</span>
            </button>
          </div>
          <div className="flex items-center gap-1 text-[11px] text-gray-400">
            <button
              onClick={() => { setSearchTarget('104.28.19.44'); handlePerformLiveQuery('104.28.19.44'); }}
              className="px-2 py-0.5 bg-white/5 hover:bg-white/10 text-gray-300 rounded border border-white/10"
            >
              Cloudflare Anycast
            </button>
            <button
              onClick={() => { setSearchTarget('185.220.101.45'); handlePerformLiveQuery('185.220.101.45'); }}
              className="px-2 py-0.5 bg-white/5 hover:bg-white/10 text-gray-300 rounded border border-white/10"
            >
              Tor Exit Relay
            </button>
          </div>
        </div>
      )}

      {/* Main View Area */}
      <div className={`relative ${isExpanded ? 'flex-1 min-h-[500px]' : isCompact ? 'h-64' : 'h-80 sm:h-96'}`}>
        
        {/* 1. 3D CYBER GLOBE MODE */}
        {viewMode === '3d-globe' && (
          <div className="relative w-full h-full cursor-grab active:cursor-grabbing select-none overflow-hidden">
            <canvas
              ref={canvasRef}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              onTouchStart={handleTouchStart}
              onTouchMove={handleTouchMove}
              onTouchEnd={handleMouseUp}
              className="w-full h-full block"
            />

            {/* Tactical 3D HUD Floating Overlays */}
            <div className="absolute top-3 left-3 pointer-events-none space-y-1 font-mono text-[10px]">
              <div className="bg-[#05080f]/85 backdrop-blur-md border border-white/10 rounded-xl p-2.5 text-gray-300 space-y-1.5 pointer-events-auto shadow-xl max-w-[240px]">
                <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-1">
                  <span className="text-gray-400 font-bold">TARGET HOST:</span>
                  <span className="text-red-400 font-bold truncate">{activeIntel.resolvedDomain || activeIntel.ip}</span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-gray-500">LOCATION:</span>
                  <span className="text-white font-bold truncate">{activeIntel.city}, {activeIntel.countryCode || activeIntel.country}</span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-gray-500">LAT / LNG:</span>
                  <span className="text-cyber-blue font-bold">{formattedCoords.lat}, {formattedCoords.lng}</span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-gray-500">ASN / ISP:</span>
                  <span className="text-gray-300 truncate max-w-[120px]">{activeIntel.asn} • {activeIntel.isp}</span>
                </div>
                <div className="flex items-center justify-between gap-2 pt-0.5">
                  <span className="text-gray-500">TELEMETRY:</span>
                  <span className={`font-bold ${activeIntel.lookupStatus === 'RESOLVED' ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {activeIntel.lookupStatus === 'RESOLVED' ? 'LIVE RESOLVED' : 'REGIONAL ESTIMATE'}
                  </span>
                </div>
              </div>
            </div>

            {/* 3D Globe Tactical Controls */}
            <div className="absolute bottom-3 right-3 flex items-center gap-1.5 bg-[#05080f]/80 backdrop-blur-md p-1.5 rounded-xl border border-white/10 font-mono text-[10px]">
              <button
                onClick={handleLockOnTarget}
                className="px-2.5 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/40 rounded-lg font-bold flex items-center gap-1 transition-all"
                title="Rotate 3D globe directly to Origin Server coordinates"
              >
                <Crosshair className="w-3 h-3" />
                <span>Lock-On</span>
              </button>

              <button
                onClick={() => setIsAutoRotating(!isAutoRotating)}
                className={`p-1.5 rounded-lg border transition-all ${
                  isAutoRotating 
                    ? 'bg-cyber-blue/20 text-cyber-blue border-cyber-blue/40' 
                    : 'bg-white/5 text-gray-400 border-white/10 hover:text-white'
                }`}
                title={isAutoRotating ? 'Pause 3D Auto-Rotation' : 'Resume 3D Auto-Rotation'}
              >
                <RotateCw className={`w-3.5 h-3.5 ${isAutoRotating ? 'animate-spin' : ''}`} style={{ animationDuration: '6s' }} />
              </button>

              <button
                onClick={() => setZoomLevel((prev) => Math.min(1.6, prev + 0.15))}
                className="px-2 py-1 bg-white/5 hover:bg-white/10 text-white rounded-lg border border-white/10 font-bold"
                title="Zoom In"
              >
                +
              </button>

              <button
                onClick={() => setZoomLevel((prev) => Math.max(0.65, prev - 0.15))}
                className="px-2 py-1 bg-white/5 hover:bg-white/10 text-white rounded-lg border border-white/10 font-bold"
                title="Zoom Out"
              >
                -
              </button>
            </div>

            <div className="absolute bottom-3 left-3 pointer-events-none text-[10px] font-mono text-gray-500 hidden sm:block">
              <span>* Click and drag to rotate 3D sphere | Scroll to adjust focal plane</span>
            </div>
          </div>
        )}

        {/* 2. GOOGLE MAPS TACTICAL RADAR MODE */}
        {viewMode === 'tactical-map' && (
          <div className="w-full h-full relative bg-[#060b14] overflow-hidden">
            <GoogleMapsTacticalRadar
              originIP={activeIntel}
              hops={hops}
              targetLocation={targetLocation}
              isCompact={isCompact}
            />
          </div>
        )}

        {/* 3. TRANSIT HOPS PHYSICAL TRAIL MODE */}
        {viewMode === 'transit-trail' && (
          <div className="w-full h-full bg-[#05080f] p-4 overflow-y-auto custom-scrollbar flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Navigation className="w-3.5 h-3.5 text-cyber-blue" />
                  SMTP Transmission Physical Topology ({transitNodes.length} Nodes)
                </span>

                <button
                  onClick={() => setIsPlayingTrail(!isPlayingTrail)}
                  className="px-3 py-1 bg-cyber-blue/15 hover:bg-cyber-blue/25 text-cyber-blue border border-cyber-blue/30 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all"
                >
                  {isPlayingTrail ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
                  <span>{isPlayingTrail ? 'Pause Replay' : 'Play Transmission Trace'}</span>
                </button>
              </div>

              {/* Hop Progression Pipeline */}
              <div className="grid grid-cols-1 gap-2.5 pt-2">
                {transitNodes.map((node, index) => {
                  const isActive = activeHopIndex === index;
                  return (
                    <div
                      key={index}
                      onClick={() => setActiveHopIndex(index)}
                      className={`p-3 rounded-xl border transition-all cursor-pointer flex items-center justify-between font-mono text-xs ${
                        isActive
                          ? 'bg-cyber-blue/10 border-cyber-blue shadow-lg text-white'
                          : 'bg-[#0a0f1c] border-white/5 hover:border-white/15 text-gray-400'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${
                          node.type === 'ORIGIN' ? 'bg-red-500 text-white' :
                          node.type === 'TARGET' ? 'bg-emerald-500 text-black' :
                          'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40'
                        }`}>
                          {index + 1}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-white font-bold">{node.name}</span>
                            <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase ${
                              node.type === 'ORIGIN' ? 'bg-red-500/20 text-red-400' :
                              node.type === 'TARGET' ? 'bg-emerald-500/20 text-emerald-400' :
                              'bg-white/10 text-gray-400'
                            }`}>
                              {node.type}
                            </span>
                          </div>
                          <span className="text-[10px] text-gray-500">IP: {node.ip} | Coords: {node.lat.toFixed(2)}°, {node.lng.toFixed(2)}°</span>
                        </div>
                      </div>

                      {isActive && (
                        <span className="text-[10px] text-cyber-blue font-bold animate-pulse">
                          ACTIVE TRACE
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="pt-3 border-t border-white/5 flex items-center justify-between text-[11px] font-mono text-gray-400">
              <span>* Reconstructs physical email path from originating mail client across relays to destination MX</span>
              <button
                onClick={() => setViewMode('3d-globe')}
                className="text-cyber-blue hover:underline flex items-center gap-1"
              >
                <span>View on 3D Globe</span>
                <Globe className="w-3 h-3" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Bottom Summary Bar */}
      <div className="px-4 py-2.5 bg-[#05080f] border-t border-white/5 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-4 text-gray-400">
          <div>
            <span className="text-[10px] text-gray-500 block">IP TYPE:</span>
            <span className="text-white">{activeIntel.ipType || 'Public IPv4'}</span>
          </div>
          <div>
            <span className="text-[10px] text-gray-500 block">ORGANIZATION / ISP:</span>
            <span className="text-white truncate max-w-[160px] block">{activeIntel.organization || activeIntel.isp}</span>
          </div>
          <div>
            <span className="text-[10px] text-gray-500 block">VPN / TOR INDICATOR:</span>
            <span className={activeIntel.vpnTorIndicator.includes('TOR') || activeIntel.vpnTorIndicator.includes('BULLETPROOF') ? 'text-red-400 font-bold' : 'text-emerald-400'}>
              {activeIntel.vpnTorIndicator || 'Standard Public Gateway'}
            </span>
          </div>
          {activeIntel.providerSource && (
            <div className="hidden md:block">
              <span className="text-[10px] text-gray-500 block">TELEMETRY SOURCE:</span>
              <span className="text-cyan-400 font-medium">{activeIntel.providerSource}</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleLockOnTarget}
            className="px-3 py-1.5 rounded-lg bg-cyber-blue/15 hover:bg-cyber-blue/25 text-cyber-blue border border-cyber-blue/30 font-bold transition-all flex items-center gap-1.5 active:scale-95"
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>Center 3D Radar</span>
          </button>
        </div>
      </div>
    </div>
  );
};
