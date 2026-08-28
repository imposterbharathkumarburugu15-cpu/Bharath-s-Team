import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { 
  Shield, 
  Bell, 
  Lock, 
  Cpu, 
  Globe, 
  Sliders, 
  CheckCircle2, 
  Terminal, 
  Eye, 
  Zap, 
  Save 
} from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';

export function Settings() {
  const { language, setLanguage, t } = useLanguage();
  const [autoQuarantine, setAutoQuarantine] = useState(true);
  const [realtimeDnsCheck, setRealtimeDnsCheck] = useState(true);
  const [deepfakeAudioScan, setDeepfakeAudioScan] = useState(true);
  const [thresholdScore, setThresholdScore] = useState(80);
  const [notifySlack, setNotifySlack] = useState(true);
  const [notifyEmail, setNotifyEmail] = useState(false);
  const [savedAlert, setSavedAlert] = useState(false);

  const handleSave = () => {
    setSavedAlert(true);
    setTimeout(() => setSavedAlert(false), 3000);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto w-full pb-10">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold font-sans tracking-wide text-white flex items-center gap-2">
            <Sliders className="w-6 h-6 text-cyber-blue" />
            SECURITY SYSTEM PREFERENCES
          </h2>
          <p className="text-cyber-muted text-xs sm:text-sm font-mono mt-1">
            Configure SOC detection thresholds, AI models, and real-time response automation.
          </p>
        </div>
        <Button 
          onClick={handleSave} 
          className="bg-cyber-blue text-black hover:bg-cyber-blue/90 font-mono text-xs font-bold gap-2 self-start sm:self-auto shadow-[0_0_15px_rgba(0,243,255,0.3)]"
        >
          <Save className="w-4 h-4" />
          SAVE CONFIGURATION
        </Button>
      </div>

      {savedAlert && (
        <div className="p-3 rounded-xl bg-cyber-green/10 border border-cyber-green/40 text-cyber-green text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-cyber-green" />
          Settings successfully synchronized with NeuroShield gateway.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Detection Engine Parameters */}
        <Card className="bg-[#0a0f1c] border-cyber-border/40">
          <CardHeader className="pb-3 border-b border-white/5">
            <CardTitle className="text-sm font-mono flex items-center gap-2 text-white">
              <Shield className="w-4 h-4 text-cyber-blue" />
              AI Threat Detection Rules
            </CardTitle>
            <p className="text-xs text-cyber-muted">
              Tune sensitivity thresholds for incoming text, email headers, and URLs.
            </p>
          </CardHeader>
          <CardContent className="space-y-5 pt-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-medium text-white">Auto-Quarantine BEC & Phishing</div>
                <div className="text-[11px] text-cyber-muted">Instantly isolate emails with DMARC fail or score &gt; 90</div>
              </div>
              <button 
                onClick={() => setAutoQuarantine(!autoQuarantine)}
                className={`w-11 h-6 rounded-full transition-colors relative ${autoQuarantine ? 'bg-cyber-blue' : 'bg-white/10'}`}
              >
                <div className={`w-4 h-4 rounded-full bg-black transition-transform absolute top-1 ${autoQuarantine ? 'right-1' : 'left-1'}`} />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-medium text-white">Real-Time DoH DNS Verification</div>
                <div className="text-[11px] text-cyber-muted">Verify SPF, DKIM, and BIMI via Cloudflare/Google DoH</div>
              </div>
              <button 
                onClick={() => setRealtimeDnsCheck(!realtimeDnsCheck)}
                className={`w-11 h-6 rounded-full transition-colors relative ${realtimeDnsCheck ? 'bg-cyber-blue' : 'bg-white/10'}`}
              >
                <div className={`w-4 h-4 rounded-full bg-black transition-transform absolute top-1 ${realtimeDnsCheck ? 'right-1' : 'left-1'}`} />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-medium text-white">Sentinel Voice Deepfake Detection</div>
                <div className="text-[11px] text-cyber-muted">Analyze live acoustic spectrograms for synthetic voices</div>
              </div>
              <button 
                onClick={() => setDeepfakeAudioScan(!deepfakeAudioScan)}
                className={`w-11 h-6 rounded-full transition-colors relative ${deepfakeAudioScan ? 'bg-cyber-blue' : 'bg-white/10'}`}
              >
                <div className={`w-4 h-4 rounded-full bg-black transition-transform absolute top-1 ${deepfakeAudioScan ? 'right-1' : 'left-1'}`} />
              </button>
            </div>

            <div className="space-y-2 pt-2 border-t border-white/5">
              <div className="flex justify-between text-xs">
                <span className="text-white font-medium">Alert Trigger Threshold</span>
                <span className="font-mono text-cyber-blue font-bold">{thresholdScore}% Risk</span>
              </div>
              <input 
                type="range" 
                min="50" 
                max="95" 
                value={thresholdScore} 
                onChange={(e) => setThresholdScore(Number(e.target.value))}
                className="w-full accent-cyber-blue h-1.5 bg-white/10 rounded-lg cursor-pointer"
              />
              <div className="flex justify-between text-[10px] font-mono text-cyber-muted">
                <span>50% (Permissive)</span>
                <span>80% (Recommended)</span>
                <span>95% (Strict)</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* System Language & Interface */}
        <Card className="bg-[#0a0f1c] border-cyber-border/40">
          <CardHeader className="pb-3 border-b border-white/5">
            <CardTitle className="text-sm font-mono flex items-center gap-2 text-white">
              <Globe className="w-4 h-4 text-cyber-green" />
              Language & Regional Localization
            </CardTitle>
            <p className="text-xs text-cyber-muted">
              Multi-lingual AI analysis and interface display language.
            </p>
          </CardHeader>
          <CardContent className="space-y-4 pt-4">
            <div className="grid grid-cols-3 gap-2">
              <button
                onClick={() => setLanguage('en')}
                className={`p-3 rounded-xl border text-center transition-all ${
                  language === 'en'
                    ? 'border-cyber-blue bg-cyber-blue/15 text-white shadow-[0_0_12px_rgba(0,243,255,0.2)]'
                    : 'border-white/10 bg-black/30 text-cyber-muted hover:text-white'
                }`}
              >
                <div className="text-sm font-bold">English</div>
                <div className="text-[10px] text-cyber-blue font-mono mt-0.5">EN-US</div>
              </button>

              <button
                onClick={() => setLanguage('hi')}
                className={`p-3 rounded-xl border text-center transition-all ${
                  language === 'hi'
                    ? 'border-cyber-blue bg-cyber-blue/15 text-white shadow-[0_0_12px_rgba(0,243,255,0.2)]'
                    : 'border-white/10 bg-black/30 text-cyber-muted hover:text-white'
                }`}
              >
                <div className="text-sm font-bold">हिन्दी</div>
                <div className="text-[10px] text-cyber-blue font-mono mt-0.5">HI-IN</div>
              </button>

              <button
                onClick={() => setLanguage('te')}
                className={`p-3 rounded-xl border text-center transition-all ${
                  language === 'te'
                    ? 'border-cyber-blue bg-cyber-blue/15 text-white shadow-[0_0_12px_rgba(0,243,255,0.2)]'
                    : 'border-white/10 bg-black/30 text-cyber-muted hover:text-white'
                }`}
              >
                <div className="text-sm font-bold">తెలుగు</div>
                <div className="text-[10px] text-cyber-blue font-mono mt-0.5">TE-IN</div>
              </button>
            </div>

            <div className="space-y-3 pt-3 border-t border-white/5">
              <div className="text-xs font-medium text-white">Notification Webhooks</div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-cyber-muted">Slack / Teams SOC Alerts</span>
                <button 
                  onClick={() => setNotifySlack(!notifySlack)}
                  className={`w-11 h-6 rounded-full transition-colors relative ${notifySlack ? 'bg-cyber-green' : 'bg-white/10'}`}
                >
                  <div className={`w-4 h-4 rounded-full bg-black transition-transform absolute top-1 ${notifySlack ? 'right-1' : 'left-1'}`} />
                </button>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-cyber-muted">Email Daily Digest</span>
                <button 
                  onClick={() => setNotifyEmail(!notifyEmail)}
                  className={`w-11 h-6 rounded-full transition-colors relative ${notifyEmail ? 'bg-cyber-green' : 'bg-white/10'}`}
                >
                  <div className={`w-4 h-4 rounded-full bg-black transition-transform absolute top-1 ${notifyEmail ? 'right-1' : 'left-1'}`} />
                </button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
