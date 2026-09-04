// Source: Google Maps Platform Code Assist
import React, { useState, useEffect, useCallback } from 'react';
import { 
  APIProvider, 
  Map, 
  AdvancedMarker, 
  Pin, 
  InfoWindow, 
  useMap 
} from '@vis.gl/react-google-maps';
import { 
  Shield, 
  ShieldAlert, 
  Server, 
  Radio, 
  Crosshair, 
  Maximize2, 
  Navigation, 
  Layers, 
  ExternalLink, 
  Key, 
  Sparkles,
  Info,
  CheckCircle2
} from 'lucide-react';
import { OriginIPIntel, HeaderHop } from '../services/forensicsEngine';

interface GoogleMapsTacticalRadarProps {
  originIP: OriginIPIntel;
  hops?: HeaderHop[];
  targetLocation?: { lat: number; lng: number; label: string };
  isCompact?: boolean;
}

interface MapTarget {
  id: string;
  type: 'origin' | 'hop' | 'target';
  title: string;
  ip: string;
  domain?: string;
  lat: number;
  lng: number;
  city?: string;
  country?: string;
  countryCode?: string;
  isp?: string;
  asn?: string;
  threatReputation?: string;
  vpnTorIndicator?: string;
  hopIndex?: number;
}

// Inner Controller to handle smooth camera animations and bounds fitting
const MapCameraController: React.FC<{
  center: { lat: number; lng: number };
  markers: MapTarget[];
  shouldFitBounds?: boolean;
}> = ({ center, markers, shouldFitBounds }) => {
  const map = useMap('cyber-forensic-map');

  useEffect(() => {
    if (!map) return;

    if (shouldFitBounds && markers.length > 1) {
      try {
        const bounds = new google.maps.LatLngBounds();
        markers.forEach(m => bounds.extend({ lat: m.lat, lng: m.lng }));
        map.fitBounds(bounds, { top: 60, right: 60, bottom: 60, left: 60 });
      } catch (err) {
        map.panTo(center);
      }
    } else {
      map.panTo(center);
    }
  }, [map, center, markers, shouldFitBounds]);

  return null;
};

export const GoogleMapsTacticalRadar: React.FC<GoogleMapsTacticalRadarProps> = ({
  originIP,
  hops = [],
  targetLocation = { lat: 37.7749, lng: -122.4194, label: 'Target Mail Gateway' },
  isCompact = false
}) => {
  const envApiKey = (import.meta as any).env?.VITE_GOOGLE_MAPS_API_KEY || '';
  const [customApiKey, setCustomApiKey] = useState<string>('');
  const [showKeyInput, setShowKeyInput] = useState<boolean>(false);
  const [mapTypeId, setMapTypeId] = useState<string>('hybrid');
  const [selectedTarget, setSelectedTarget] = useState<MapTarget | null>(null);
  const [fitAllBounds, setFitAllBounds] = useState<boolean>(false);

  const activeApiKey = customApiKey.trim() || envApiKey.trim();

  // Extract coordinates and normalize markers list
  const originLat = originIP.latitude ?? 37.7749;
  const originLng = originIP.longitude ?? -122.4194;

  const markers: MapTarget[] = [
    {
      id: 'origin-node',
      type: 'origin',
      title: 'Origin Threat Host / Sender',
      ip: originIP.ip,
      domain: originIP.resolvedDomain,
      lat: originLat,
      lng: originLng,
      city: originIP.city,
      country: originIP.country,
      countryCode: originIP.countryCode,
      isp: originIP.isp,
      asn: originIP.asn,
      threatReputation: originIP.threatReputation,
      vpnTorIndicator: originIP.vpnTorIndicator
    },
    ...hops.map((h, idx) => ({
      id: `hop-${idx}`,
      type: 'hop' as const,
      title: `SMTP Relay Hop #${idx + 1}`,
      ip: h.sourceIP || `Relay-${idx + 1}`,
      domain: h.sourceHostname || h.destinationHostname,
      lat: h.latitude ?? (originLat + (idx + 1) * 2.2),
      lng: h.longitude ?? (originLng + (idx + 1) * 3.5),
      city: h.city || 'Transit Point-of-Presence',
      country: h.country || 'International',
      countryCode: h.countryCode || 'UN',
      isp: 'SMTP Relay Transit Provider',
      asn: 'AS-TRANSIT',
      hopIndex: idx + 1
    })),
    {
      id: 'target-gateway',
      type: 'target',
      title: targetLocation.label || 'Target Mail MX Gateway',
      ip: 'Internal Ingress MX',
      lat: targetLocation.lat,
      lng: targetLocation.lng,
      city: 'San Francisco, CA',
      country: 'United States',
      countryCode: 'US',
      isp: 'Cloud Security Ingress Edge',
      asn: 'AS-CORP'
    }
  ];

  const handleCenterOnOrigin = useCallback(() => {
    setFitAllBounds(false);
    setSelectedTarget(markers[0]);
  }, [markers]);

  return (
    <div className="w-full h-full relative bg-[#060b14] overflow-hidden flex flex-col font-sans">
      {/* Top Tactical GIS HUD Bar */}
      <div className="bg-[#05080f]/90 border-b border-white/10 px-3 py-2 flex flex-wrap items-center justify-between gap-2 z-10 font-mono text-xs">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-cyber-blue font-bold">
            <Radio className="w-3.5 h-3.5 text-red-400 animate-pulse" />
            <span className="text-[11px] tracking-wider">GOOGLE MAPS™ PLATFORM FORENSICS</span>
          </div>
          <span className="text-[10px] bg-cyan-500/10 text-cyan-300 px-2 py-0.5 rounded border border-cyan-500/20 hidden sm:inline">
            SDK v1.9 + AdvancedMarkerElement
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          {/* Map Type Controls */}
          <div className="flex items-center bg-[#0a1224] p-0.5 rounded-lg border border-white/10 text-[10px]">
            <button
              onClick={() => setMapTypeId('hybrid')}
              className={`px-2 py-0.5 rounded transition-all ${mapTypeId === 'hybrid' ? 'bg-cyber-blue text-black font-bold' : 'text-gray-400 hover:text-white'}`}
            >
              Satellite
            </button>
            <button
              onClick={() => setMapTypeId('roadmap')}
              className={`px-2 py-0.5 rounded transition-all ${mapTypeId === 'roadmap' ? 'bg-cyber-blue text-black font-bold' : 'text-gray-400 hover:text-white'}`}
            >
              Roadmap
            </button>
            <button
              onClick={() => setMapTypeId('terrain')}
              className={`px-2 py-0.5 rounded transition-all ${mapTypeId === 'terrain' ? 'bg-cyber-blue text-black font-bold' : 'text-gray-400 hover:text-white'}`}
            >
              Terrain
            </button>
          </div>

          <button
            onClick={() => setFitAllBounds(prev => !prev)}
            title="Fit view to all transit hops"
            className={`px-2 py-1 rounded-lg border text-[10px] font-bold flex items-center gap-1 transition-all ${
              fitAllBounds ? 'bg-cyber-blue/20 text-cyber-blue border-cyber-blue/40' : 'bg-white/5 text-gray-300 border-white/10 hover:bg-white/10'
            }`}
          >
            <Navigation className="w-3 h-3" />
            <span>Fit Trail</span>
          </button>

          <button
            onClick={handleCenterOnOrigin}
            title="Lock camera on Origin Host coordinates"
            className="px-2 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/40 rounded-lg text-[10px] font-bold flex items-center gap-1 transition-all"
          >
            <Crosshair className="w-3 h-3" />
            <span>Origin Lock</span>
          </button>

          <button
            onClick={() => setShowKeyInput(!showKeyInput)}
            title="Configure Google Maps API Key or Demo Key"
            className="p-1 text-gray-400 hover:text-white bg-white/5 rounded-lg border border-white/10 transition-colors"
          >
            <Key className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Optional In-Map API Key Input Drawer */}
      {showKeyInput && (
        <div className="bg-[#05080f] px-4 py-2 border-b border-white/10 flex flex-wrap items-center gap-2 text-xs font-mono z-10">
          <span className="text-gray-300 font-bold flex items-center gap-1">
            <Key className="w-3.5 h-3.5 text-cyber-blue" />
            GOOGLE MAPS API KEY:
          </span>
          <input
            type="text"
            value={customApiKey}
            onChange={(e) => setCustomApiKey(e.target.value)}
            placeholder="Paste your Google Maps API Key or Demo Key"
            className="flex-1 min-w-[240px] bg-[#0a1224] border border-white/15 rounded-lg px-3 py-1 text-white placeholder-gray-500 font-mono text-xs focus:outline-none focus:border-cyber-blue"
          />
          <a
            href="https://mapsplatform.google.com/maps-demo-key?utm_campaign=gmp_mcp_codeassist_v1_aistudio"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[11px] text-cyber-blue hover:underline flex items-center gap-1"
          >
            <span>Get Free Maps Demo Key</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      )}

      {/* Main Map Container */}
      <div className="w-full flex-1 relative min-h-[300px]">
        {activeApiKey ? (
          <APIProvider apiKey={activeApiKey}>
            <Map
              id="cyber-forensic-map"
              mapId="DEMO_MAP_ID"
              defaultCenter={{ lat: originLat, lng: originLng }}
              defaultZoom={11}
              mapTypeId={mapTypeId}
              className="w-full h-full"
              disableDefaultUI={false}
              gestureHandling="greedy"
              internalUsageAttributionIds={["gmp_mcp_codeassist_v1_aistudio"]}
            >
              <MapCameraController
                center={{ lat: originLat, lng: originLng }}
                markers={markers}
                shouldFitBounds={fitAllBounds}
              />

              {/* Render Advanced Markers */}
              {markers.map((marker) => {
                const isOrigin = marker.type === 'origin';
                const isTarget = marker.type === 'target';

                return (
                  <AdvancedMarker
                    key={marker.id}
                    position={{ lat: marker.lat, lng: marker.lng }}
                    onClick={() => setSelectedTarget(marker)}
                    title={marker.title}
                  >
                    {isOrigin ? (
                      <div className="relative flex items-center justify-center cursor-pointer group">
                        <div className="w-9 h-9 rounded-full bg-red-500/40 animate-ping absolute" />
                        <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-red-600 to-amber-500 border-2 border-white shadow-xl flex items-center justify-center text-white text-xs font-black ring-2 ring-red-500/50">
                          !
                        </div>
                        <span className="absolute -bottom-5 bg-black/90 text-red-400 text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border border-red-500/30 whitespace-nowrap shadow-md">
                          ORIGIN: {marker.ip}
                        </span>
                      </div>
                    ) : isTarget ? (
                      <div className="relative flex items-center justify-center cursor-pointer">
                        <div className="w-7 h-7 rounded-full bg-emerald-600 border-2 border-white shadow-xl flex items-center justify-center text-white text-xs font-bold ring-2 ring-emerald-500/50">
                          <Shield className="w-3.5 h-3.5" />
                        </div>
                        <span className="absolute -bottom-5 bg-black/90 text-emerald-400 text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border border-emerald-500/30 whitespace-nowrap shadow-md">
                          TARGET MX
                        </span>
                      </div>
                    ) : (
                      <div className="relative flex items-center justify-center cursor-pointer">
                        <div className="w-6 h-6 rounded-full bg-amber-600 border border-white shadow-md flex items-center justify-center text-white text-[10px] font-bold font-mono">
                          {marker.hopIndex}
                        </div>
                      </div>
                    )}
                  </AdvancedMarker>
                );
              })}

              {/* InfoWindow for clicked marker */}
              {selectedTarget && (
                <InfoWindow
                  position={{ lat: selectedTarget.lat, lng: selectedTarget.lng }}
                  onCloseClick={() => setSelectedTarget(null)}
                  maxWidth={320}
                >
                  <div className="bg-[#05080f] text-gray-200 p-2.5 rounded-lg font-mono text-xs space-y-2 border border-white/10 shadow-2xl">
                    <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-1.5">
                      <span className={`font-bold uppercase tracking-wider text-[11px] ${
                        selectedTarget.type === 'origin' ? 'text-red-400' : selectedTarget.type === 'target' ? 'text-emerald-400' : 'text-amber-400'
                      }`}>
                        {selectedTarget.title}
                      </span>
                      <span className="text-[10px] text-gray-400">{selectedTarget.countryCode || 'UN'}</span>
                    </div>

                    <div className="space-y-1 text-[11px]">
                      <div className="flex justify-between gap-2">
                        <span className="text-gray-400">IP ADDRESS:</span>
                        <span className="text-white font-bold">{selectedTarget.ip}</span>
                      </div>
                      {selectedTarget.domain && (
                        <div className="flex justify-between gap-2">
                          <span className="text-gray-400">HOST / DOMAIN:</span>
                          <span className="text-cyan-300 font-bold truncate max-w-[150px]">{selectedTarget.domain}</span>
                        </div>
                      )}
                      <div className="flex justify-between gap-2">
                        <span className="text-gray-400">GEO LOCATION:</span>
                        <span className="text-gray-200">{selectedTarget.city || 'Unknown'}, {selectedTarget.country}</span>
                      </div>
                      <div className="flex justify-between gap-2">
                        <span className="text-gray-400">COORDINATES:</span>
                        <span className="text-cyber-blue font-bold">{selectedTarget.lat.toFixed(4)}°, {selectedTarget.lng.toFixed(4)}°</span>
                      </div>
                      <div className="flex justify-between gap-2">
                        <span className="text-gray-400">ISP / CARRIER:</span>
                        <span className="text-gray-300 truncate max-w-[150px]">{selectedTarget.isp}</span>
                      </div>
                      <div className="flex justify-between gap-2">
                        <span className="text-gray-400">AUTONOMOUS SYS:</span>
                        <span className="text-gray-300">{selectedTarget.asn}</span>
                      </div>
                    </div>

                    {selectedTarget.vpnTorIndicator && (
                      <div className="bg-red-500/10 border border-red-500/30 rounded p-1.5 text-[10px] text-red-300">
                        <span className="font-bold">EVASION INDICATOR: </span>
                        {selectedTarget.vpnTorIndicator}
                      </div>
                    )}

                    <div className="pt-1 border-t border-white/10 flex items-center justify-between text-[10px]">
                      <a
                        href={`https://www.google.com/maps/search/?api=1&query=${selectedTarget.lat},${selectedTarget.lng}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyber-blue hover:underline flex items-center gap-1 font-bold"
                      >
                        <span>Open Street View / Maps</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                </InfoWindow>
              )}
            </Map>
          </APIProvider>
        ) : (
          /* Zero-friction Google Maps Setup / Demo Key Quickstart UI */
          <div className="w-full h-full relative flex flex-col items-center justify-center bg-[#070f1e] p-6 text-center select-none overflow-y-auto">
            {/* Embedded Live GIS Satellite Layer Simulation */}
            <iframe
              title="Tactical Satellite Map Preview"
              src={`https://www.openstreetmap.org/export/embed.html?bbox=${originLng - 0.2}%2C${originLat - 0.15}%2C${originLng + 0.2}%2C${originLat + 0.15}&layer=mapnik&marker=${originLat}%2C${originLng}`}
              className="absolute inset-0 w-full h-full border-0 filter invert contrast-125 brightness-75 hue-rotate-180 opacity-40 pointer-events-none"
            />

            <div className="relative z-10 max-w-md bg-[#05080f]/95 border border-cyber-blue/30 rounded-2xl p-5 shadow-2xl backdrop-blur-xl space-y-4">
              <div className="flex items-center justify-center gap-2 text-cyber-blue">
                <div className="w-10 h-10 rounded-xl bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center">
                  <Layers className="w-5 h-5 text-cyber-blue" />
                </div>
              </div>

              <div>
                <h4 className="text-white font-bold text-base font-sans">
                  Google Maps™ Platform Tactical Geolocation
                </h4>
                <p className="text-gray-400 text-xs mt-1 font-sans">
                  Inspect high-resolution photorealistic satellite imagery, terrain topology, and real-time transit hop vectors for origin host <span className="text-red-400 font-mono font-bold">{originIP.ip}</span> ({originIP.city}, {originIP.country}).
                </p>
              </div>

              <div className="bg-[#0a1224] border border-white/10 rounded-xl p-3 text-left space-y-2 text-xs font-mono">
                <div className="text-gray-300 font-bold flex items-center gap-1.5 text-[11px]">
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                  <span>Free Prototyping Demo Key:</span>
                </div>
                <p className="text-gray-400 text-[11px]">
                  Sign in with any Google account to generate a zero-cost Maps Demo Key (no billing required) or paste an existing Google Cloud API Key.
                </p>
                <div className="flex flex-col sm:flex-row gap-2 pt-1">
                  <a
                    href="https://mapsplatform.google.com/maps-demo-key?utm_campaign=gmp_mcp_codeassist_v1_aistudio"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex-1 px-3 py-2 bg-gradient-to-r from-cyber-blue to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-black font-bold rounded-lg text-center text-xs flex items-center justify-center gap-1.5 transition-all shadow-lg"
                  >
                    <span>Get Free Maps Demo Key</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                  <button
                    onClick={() => setShowKeyInput(true)}
                    className="px-3 py-2 bg-white/10 hover:bg-white/15 text-white font-bold rounded-lg text-xs flex items-center justify-center gap-1.5 transition-all border border-white/10"
                  >
                    <Key className="w-3.5 h-3.5" />
                    <span>Enter Key</span>
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between text-[10px] font-mono text-gray-500 pt-1 border-t border-white/10">
                <span>LAT: {originLat.toFixed(4)}° / LNG: {originLng.toFixed(4)}°</span>
                <a
                  href={`https://www.google.com/maps/search/?api=1&query=${originLat},${originLng}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyber-blue hover:underline flex items-center gap-1 font-bold"
                >
                  <span>Open in Google Maps</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bottom Live Geolocation Status Bar */}
      <div className="bg-[#05080f]/90 border-t border-white/10 px-3 py-2 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-gray-400">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="text-gray-500">TARGET:</span>
            <span className="text-red-400 font-bold">{originIP.resolvedDomain || originIP.ip}</span>
          </div>
          <div className="hidden sm:flex items-center gap-1.5">
            <span className="text-gray-500">GEO:</span>
            <span className="text-white">{originIP.city}, {originIP.countryCode || originIP.country}</span>
          </div>
          <div className="hidden md:flex items-center gap-1.5">
            <span className="text-gray-500">ASN / ISP:</span>
            <span className="text-gray-300">{originIP.asn} • {originIP.isp}</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded">
            {originIP.vpnTorIndicator || 'Standard ISP Transit'}
          </span>
        </div>
      </div>
    </div>
  );
};
