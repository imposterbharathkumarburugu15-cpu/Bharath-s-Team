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
  ExternalLink
} from 'lucide-react';
import { OriginIPIntel, HeaderHop } from '../services/forensicsEngine';
import { APIProvider, Map, AdvancedMarker, Pin } from '@vis.gl/react-google-maps';

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
  const [viewMode, setViewMode] = useState<'3d-globe' | 'tactical-map' | 'transit-trail'>('3d-globe');
  const [isAutoRotating, setIsAutoRotating] = useState<boolean>(true);
  const [isExpanded, setIsExpanded] = useState<boolean>(false);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [activeHopIndex, setActiveHopIndex] = useState<number>(0);
  const [isPlayingTrail, setIsPlayingTrail] = useState<boolean>(false);
  const [mapLayer, setMapLayer] = useState<'dark-vector' | 'satellite'>('dark-vector');
  const [cursorCoords, setCursorCoords] = useState<{ lat: number; lng: number } | null>(null);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const animationFrameRef = useRef<number | null>(null);

  // 3D Globe Spherical Angles (in radians)
  const rotationYRef = useRef<number>(((-originIP.longitude || 0) * Math.PI) / 180);
  const rotationXRef = useRef<number>(((originIP.latitude || 30) * Math.PI) / 180 * 0.4);
  const targetRotationYRef = useRef<number>(((-originIP.longitude || 0) * Math.PI) / 180);
  const targetRotationXRef = useRef<number>(((originIP.latitude || 30) * Math.PI) / 180 * 0.4);
  const isDraggingRef = useRef<boolean>(false);
  const lastMousePosRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const pulsePhaseRef = useRef<number>(0);

  const googleMapsApiKey = (import.meta as any).env?.VITE_GOOGLE_MAPS_API_KEY || '';

  const originLat = originIP.latitude ?? 50.1109;
  const originLng = originIP.longitude ?? 8.6821;

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
        name: `Origin Mail Server (${originIP.city || 'Origin Node'})`,
        ip: originIP.ip,
        lat: originLat,
        lng: originLng,
        type: 'ORIGIN'
      }
    ];

    if (hops && hops.length > 0) {
      hops.forEach((h, idx) => {
        // Distribute relay hops visually across path if coordinates not in header
        const fraction = (idx + 1) / (hops.length + 1);
        const midLat = originLat + (targetLocation.lat - originLat) * fraction + (idx % 2 === 0 ? 5 : -5);
        const midLng = originLng + (targetLocation.lng - originLng) * fraction;
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
      name: `Target Mail Gateway (${targetLocation.label})`,
      ip: '104.244.42.1',
      lat: targetLocation.lat,
      lng: targetLocation.lng,
      type: 'TARGET'
    });

    return nodes;
  }, [originIP, originLat, originLng, hops, targetLocation]);

  // Trail Animation Player
  useEffect(() => {
    let interval: any;
    if (isPlayingTrail) {
      interval = setInterval(() => {
        setActiveHopIndex((prev) => {
          if (prev >= transitNodes.length - 1) {
            setIsPlayingTrail(false);
            return 0;
          }
          return prev + 1;
        });
      }, 1500);
    }
    return () => clearInterval(interval);
  }, [isPlayingTrail, transitNodes.length]);

  // 3D Canvas Rendering Engine
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || viewMode !== '3d-globe') return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let isRunning = true;

    const render = () => {
      if (!isRunning) return;

      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }

      ctx.clearRect(0, 0, width, height);

      const centerX = width / 2;
      const centerY = height / 2;
      const radius = Math.min(width, height) * 0.38 * zoomLevel;

      // Update rotation
      if (isAutoRotating) {
        rotationYRef.current += 0.0035;
        targetRotationYRef.current = rotationYRef.current;
      } else {
        rotationYRef.current += (targetRotationYRef.current - rotationYRef.current) * 0.08;
        rotationXRef.current += (targetRotationXRef.current - rotationXRef.current) * 0.08;
      }

      const rotY = rotationYRef.current;
      const rotX = rotationXRef.current;
      pulsePhaseRef.current = (pulsePhaseRef.current + 0.04) % (Math.PI * 2);

      // 1. Draw Outer Celestial Atmosphere Glow
      const atmosGlow = ctx.createRadialGradient(centerX, centerY, radius * 0.85, centerX, centerY, radius * 1.35);
      atmosGlow.addColorStop(0, 'rgba(0, 245, 255, 0.0)');
      atmosGlow.addColorStop(0.7, 'rgba(0, 245, 255, 0.08)');
      atmosGlow.addColorStop(0.9, 'rgba(0, 180, 255, 0.18)');
      atmosGlow.addColorStop(1, 'rgba(0, 245, 255, 0.0)');
      ctx.fillStyle = atmosGlow;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 1.35, 0, Math.PI * 2);
      ctx.fill();

      // 2. Draw 3D Globe Base Sphere
      const globeGrad = ctx.createRadialGradient(
        centerX - radius * 0.35,
        centerY - radius * 0.35,
        radius * 0.1,
        centerX,
        centerY,
        radius
      );
      globeGrad.addColorStop(0, '#0d192e');
      globeGrad.addColorStop(0.6, '#060d1a');
      globeGrad.addColorStop(1, '#02060d');

      ctx.fillStyle = globeGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.fill();

      // Globe Rim Accent
      ctx.strokeStyle = 'rgba(0, 245, 255, 0.4)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Helper function to project spherical coordinates (lat, lng) to 2D canvas (x, y, z)
      const project = (lat: number, lng: number, alt: number = 0) => {
        const phi = (lat * Math.PI) / 180;
        const theta = (lng * Math.PI) / 180 + rotY;

        // 3D Cartesian coordinates
        let x = (radius + alt) * Math.cos(phi) * Math.sin(theta);
        let y = -(radius + alt) * Math.sin(phi);
        let z = (radius + alt) * Math.cos(phi) * Math.cos(theta);

        // Apply X-axis rotation (Pitch)
        const cosX = Math.cos(rotX);
        const sinX = Math.sin(rotX);
        const yRot = y * cosX - z * sinX;
        const zRot = y * sinX + z * cosX;

        return {
          x: centerX + x,
          y: centerY + yRot,
          z: zRot,
          isVisible: zRot > -radius * 0.15
        };
      };

      // 3. Draw Latitude & Longitude Graticule Lines
      ctx.lineWidth = 0.75;
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let started = false;
        for (let lng = -180; lng <= 180; lng += 10) {
          const pt = project(lat, lng);
          if (pt.z > 0) {
            ctx.strokeStyle = `rgba(0, 245, 255, ${0.08 * (pt.z / radius)})`;
            if (!started) {
              ctx.moveTo(pt.x, pt.y);
              started = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }

      // Meridians
      for (let lng = -180; lng < 180; lng += 45) {
        ctx.beginPath();
        let started = false;
        for (let lat = -80; lat <= 80; lat += 10) {
          const pt = project(lat, lng);
          if (pt.z > 0) {
            ctx.strokeStyle = `rgba(0, 245, 255, ${0.08 * (pt.z / radius)})`;
            if (!started) {
              ctx.moveTo(pt.x, pt.y);
              started = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }

      // 4. Draw Continents with Cyber Glow Matrix
      CONTINENT_POLYGONS.forEach((polygon) => {
        // Draw polygon outline
        ctx.beginPath();
        let started = false;
        for (let i = 0; i < polygon.length; i++) {
          const [lat, lng] = polygon[i];
          const pt = project(lat, lng);
          if (pt.z > -radius * 0.1) {
            const alpha = Math.max(0.1, (pt.z + radius * 0.1) / (radius * 1.1));
            ctx.strokeStyle = `rgba(0, 245, 255, ${alpha * 0.45})`;
            ctx.lineWidth = 1.2;
            if (!started) {
              ctx.moveTo(pt.x, pt.y);
              started = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            started = false;
          }
        }
        ctx.stroke();

        // Draw internal dot vertices
        for (let i = 0; i < polygon.length; i += 2) {
          const [lat, lng] = polygon[i];
          const pt = project(lat, lng);
          if (pt.z > 0) {
            const alpha = pt.z / radius;
            ctx.fillStyle = `rgba(0, 245, 255, ${alpha * 0.7})`;
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 1.5, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      });

      // 5. Draw 3D Parabolic Attack Vector Trajectory Arc (Origin -> Target)
      const originPt = project(originLat, originLng, 0);
      const targetPt = project(targetLocation.lat, targetLocation.lng, 0);

      if (originPt.isVisible || targetPt.isVisible) {
        ctx.beginPath();
        const steps = 40;
        const arcPoints: { x: number; y: number; z: number }[] = [];

        for (let i = 0; i <= steps; i++) {
          const t = i / steps;
          const curLat = originLat + (targetLocation.lat - originLat) * t;
          const curLng = originLng + (targetLocation.lng - originLng) * t;
          // Parabolic altitude lift
          const altitude = Math.sin(t * Math.PI) * (radius * 0.35);
          const p = project(curLat, curLng, altitude);
          arcPoints.push(p);

          if (p.z > -radius * 0.2) {
            if (i === 0) ctx.moveTo(p.x, p.y);
            else ctx.lineTo(p.x, p.y);
          }
        }

        ctx.strokeStyle = 'rgba(255, 70, 70, 0.4)';
        ctx.lineWidth = 2;
        ctx.setLineDash([4, 4]);
        ctx.stroke();
        ctx.setLineDash([]);

        // Animated glowing photon particle along trajectory
        const particleT = (pulsePhaseRef.current / (Math.PI * 2));
        const particleIdx = Math.floor(particleT * (arcPoints.length - 1));
        const particlePt = arcPoints[particleIdx];

        if (particlePt && particlePt.z > 0) {
          const particleGlow = ctx.createRadialGradient(particlePt.x, particlePt.y, 0, particlePt.x, particlePt.y, 12);
          particleGlow.addColorStop(0, '#ff3366');
          particleGlow.addColorStop(0.5, 'rgba(255, 51, 102, 0.6)');
          particleGlow.addColorStop(1, 'rgba(255, 51, 102, 0)');
          ctx.fillStyle = particleGlow;
          ctx.beginPath();
          ctx.arc(particlePt.x, particlePt.y, 12, 0, Math.PI * 2);
          ctx.fill();

          ctx.fillStyle = '#ffffff';
          ctx.beginPath();
          ctx.arc(particlePt.x, particlePt.y, 3, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      // 6. Draw Origin Threat Server Pinpoint & 3D Sonar Pulse
      if (originPt.z > -radius * 0.1) {
        const depthAlpha = Math.max(0.2, (originPt.z + radius * 0.1) / (radius * 1.1));

        // Sonar expanding rings
        const pulseRadius1 = 10 + (Math.sin(pulsePhaseRef.current) + 1) * 8;
        const pulseRadius2 = 18 + (Math.sin(pulsePhaseRef.current + Math.PI / 2) + 1) * 12;

        ctx.strokeStyle = `rgba(255, 50, 50, ${depthAlpha * (1 - (pulseRadius1 - 10) / 16)})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(originPt.x, originPt.y, pulseRadius1, 0, Math.PI * 2);
        ctx.stroke();

        ctx.strokeStyle = `rgba(255, 100, 50, ${depthAlpha * (1 - (pulseRadius2 - 18) / 24) * 0.6})`;
        ctx.beginPath();
        ctx.arc(originPt.x, originPt.y, pulseRadius2, 0, Math.PI * 2);
        ctx.stroke();

        // Origin Beacon Pin
        ctx.fillStyle = `rgba(255, 51, 102, ${depthAlpha})`;
        ctx.beginPath();
        ctx.arc(originPt.x, originPt.y, 5, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(originPt.x, originPt.y, 2, 0, Math.PI * 2);
        ctx.fill();

        // 3D Altitude Beacon Beam
        ctx.strokeStyle = `rgba(255, 51, 102, ${depthAlpha * 0.8})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(originPt.x, originPt.y);
        ctx.lineTo(originPt.x, originPt.y - 25);
        ctx.stroke();

        // Tactical HUD Box next to origin
        if (originPt.z > 0) {
          const tagX = originPt.x + 12;
          const tagY = originPt.y - 30;

          ctx.fillStyle = 'rgba(5, 10, 20, 0.85)';
          ctx.strokeStyle = 'rgba(255, 51, 102, 0.7)';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.roundRect(tagX, tagY, 110, 32, 4);
          ctx.fill();
          ctx.stroke();

          ctx.fillStyle = '#ff4d6d';
          ctx.font = 'bold 9px "JetBrains Mono", monospace';
          ctx.fillText('ORIGIN SERVER', tagX + 6, tagY + 12);

          ctx.fillStyle = '#ffffff';
          ctx.font = '8px "JetBrains Mono", monospace';
          ctx.fillText(`${originIP.city || 'Server'}, ${originIP.country || 'Host'}`, tagX + 6, tagY + 24);
        }
      }

      // 7. Draw Target Destination Node Pin
      if (targetPt.z > -radius * 0.1) {
        const depthAlpha = Math.max(0.2, (targetPt.z + radius * 0.1) / (radius * 1.1));

        ctx.fillStyle = `rgba(0, 245, 255, ${depthAlpha})`;
        ctx.beginPath();
        ctx.arc(targetPt.x, targetPt.y, 4, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(targetPt.x, targetPt.y, 1.5, 0, Math.PI * 2);
        ctx.fill();

        if (targetPt.z > 0) {
          const tagX = targetPt.x + 10;
          const tagY = targetPt.y + 10;
          ctx.fillStyle = 'rgba(5, 10, 20, 0.85)';
          ctx.strokeStyle = 'rgba(0, 245, 255, 0.6)';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.roundRect(tagX, tagY, 95, 24, 4);
          ctx.fill();
          ctx.stroke();

          ctx.fillStyle = '#00f5ff';
          ctx.font = 'bold 8px "JetBrains Mono", monospace';
          ctx.fillText('TARGET GATEWAY', tagX + 5, tagY + 11);
          ctx.fillStyle = '#94a3b8';
          ctx.font = '7.5px "JetBrains Mono", monospace';
          ctx.fillText(targetLocation.label.slice(0, 18), tagX + 5, tagY + 20);
        }
      }

      // 8. Draw Orbital Horizon Compass Ring
      ctx.strokeStyle = 'rgba(0, 245, 255, 0.15)';
      ctx.lineWidth = 1;
      ctx.setLineDash([2, 6]);
      ctx.beginPath();
      ctx.ellipse(centerX, centerY, radius * 1.25, radius * 0.4, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);

      animationFrameRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      isRunning = false;
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current);
    };
  }, [viewMode, originLat, originLng, targetLocation, originIP, isAutoRotating, zoomLevel]);

  return (
    <div className={`relative bg-[#070c18] border border-white/10 rounded-2xl overflow-hidden shadow-2xl transition-all ${
      isExpanded ? 'fixed inset-4 z-50 flex flex-col' : 'w-full'
    }`}>
      {/* Top Cyber HUD Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 bg-[#0a1224]/80 border-b border-white/10 backdrop-blur-md">
        <div className="flex items-center gap-2.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-white font-mono uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-cyber-blue" />
                GEOSPATIAL FORENSIC 3D RADAR
              </span>
              <span className="text-[9px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.2 rounded uppercase">
                LAT/LNG LOCKED
              </span>
            </div>
            <span className="text-[10px] text-gray-400 font-mono">
              {originIP.city || 'Autonomous City'}, {originIP.country || 'Origin Nation'} — {formattedCoords.lat}, {formattedCoords.lng}
            </span>
          </div>
        </div>

        {/* View Mode Switcher */}
        <div className="flex items-center gap-1 bg-[#05080f] p-1 rounded-xl border border-white/10">
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
            <span>Tactical Map</span>
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
              <div className="bg-[#05080f]/80 backdrop-blur-sm border border-white/10 rounded-lg p-2 text-gray-300 space-y-1 pointer-events-auto">
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500">TARGET NODE:</span>
                  <span className="text-red-400 font-bold">{originIP.ip}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500">LAT / LNG:</span>
                  <span className="text-cyber-blue font-bold">{formattedCoords.lat}, {formattedCoords.lng}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500">ASN / ISP:</span>
                  <span className="text-white truncate max-w-[140px]">{originIP.asn}</span>
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

        {/* 2. TACTICAL 2D/3D SATELLITE MAP MODE */}
        {viewMode === 'tactical-map' && (
          <div className="w-full h-full relative bg-[#060b14] overflow-hidden">
            {googleMapsApiKey ? (
              <APIProvider apiKey={googleMapsApiKey}>
                <Map
                  defaultCenter={{ lat: originLat, lng: originLng }}
                  defaultZoom={11}
                  mapId="DEMO_MAP_ID"
                  className="w-full h-full"
                  disableDefaultUI={false}
                  internalUsageAttributionIds={["gmp_mcp_codeassist_v1_aistudio"]}
                >
                  <AdvancedMarker position={{ lat: originLat, lng: originLng }}>
                    <div className="relative flex items-center justify-center">
                      <div className="w-8 h-8 rounded-full bg-red-500/30 animate-ping absolute" />
                      <div className="w-5 h-5 rounded-full bg-red-600 border-2 border-white shadow-lg flex items-center justify-center text-white text-[9px] font-bold">
                        !
                      </div>
                    </div>
                  </AdvancedMarker>
                </Map>
              </APIProvider>
            ) : (
              // High-precision Cyber Dark Interactive Map Simulation & Satellite Tile Overlay
              <div className="w-full h-full relative flex items-center justify-center bg-[#070f1e] select-none">
                {/* Embedded High-Contrast Tactical Map Grid */}
                <iframe
                  title="Tactical Map"
                  src={`https://www.openstreetmap.org/export/embed.html?bbox=${originLng - 0.15}%2C${originLat - 0.1}%2C${originLng + 0.15}%2C${originLat + 0.1}&layer=mapnik&marker=${originLat}%2C${originLng}`}
                  className="w-full h-full border-0 filter invert contrast-125 brightness-90 hue-rotate-180 opacity-80"
                />

                {/* Cyber Targeting Crosshair Overlay */}
                <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
                  <div className="w-24 h-24 border border-red-500/40 rounded-full flex items-center justify-center animate-pulse">
                    <div className="w-12 h-12 border border-cyber-blue/60 rounded-full flex items-center justify-center">
                      <Crosshair className="w-6 h-6 text-red-400" />
                    </div>
                  </div>
                </div>

                {/* Live Tactical HUD Banner */}
                <div className="absolute top-3 left-3 bg-[#05080f]/90 border border-white/10 rounded-xl p-3 backdrop-blur-md font-mono text-xs max-w-xs space-y-1.5">
                  <div className="flex items-center gap-2 text-cyber-blue font-bold text-[11px]">
                    <Radio className="w-3.5 h-3.5 text-red-400 animate-pulse" />
                    <span>PRECISION TARGET RADAR</span>
                  </div>
                  <div className="text-white text-xs font-bold truncate">
                    {originIP.city}, {originIP.region}, {originIP.country}
                  </div>
                  <div className="text-[10px] text-gray-400">
                    Coords: <span className="text-gray-200">{formattedCoords.lat}, {formattedCoords.lng}</span>
                  </div>
                  <div className="text-[10px] text-gray-400">
                    ISP Gateway: <span className="text-gray-200">{originIP.isp}</span>
                  </div>
                </div>

                {/* Google Maps API Key Notice / Direct Link */}
                <div className="absolute bottom-3 right-3 bg-[#05080f]/90 border border-white/10 rounded-xl p-2.5 backdrop-blur-md font-mono text-[10px] text-gray-400 flex items-center gap-2">
                  <span>Open in external GIS:</span>
                  <a
                    href={`https://www.google.com/maps/search/?api=1&query=${originLat},${originLng}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyber-blue hover:underline flex items-center gap-1 font-bold"
                  >
                    <span>Google Maps</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            )}
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
            <span className="text-white">{originIP.ipType || 'Public IPv4'}</span>
          </div>
          <div>
            <span className="text-[10px] text-gray-500 block">ORGANIZATION:</span>
            <span className="text-white truncate max-w-[160px] block">{originIP.organization || originIP.isp}</span>
          </div>
          <div>
            <span className="text-[10px] text-gray-500 block">VPN / TOR RISK:</span>
            <span className={originIP.vpnTorIndicator.includes('TOR') || originIP.vpnTorIndicator.includes('BULLETPROOF') ? 'text-red-400 font-bold' : 'text-emerald-400'}>
              {originIP.vpnTorIndicator || 'Low Threat Indicator'}
            </span>
          </div>
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
