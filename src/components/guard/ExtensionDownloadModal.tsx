import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  X, 
  Download, 
  Check, 
  Chrome, 
  FolderDown, 
  ShieldCheck, 
  Sparkles, 
  Terminal, 
  Sliders, 
  ExternalLink,
  Zap,
  Copy
} from 'lucide-react';
import JSZip from 'jszip';

interface ExtensionDownloadModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ExtensionDownloadModal({ isOpen, onClose }: ExtensionDownloadModalProps) {
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadSuccess, setDownloadSuccess] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState(false);

  const manifestContent = `{
  "manifest_version": 3,
  "name": "NeuroShield Guard — Real-Time Phishing & Scam Defense",
  "version": "1.1.0",
  "description": "Real-time client for NeuroShield Core. Inspects suspicious links, QR codes, SMS, and credentials before dangerous actions.",
  "permissions": [
    "activeTab",
    "storage",
    "contextMenus",
    "alarms",
    "tabs",
    "webNavigation"
  ],
  "host_permissions": [
    "<all_urls>"
  ],
  "action": {
    "default_popup": "popup.html",
    "default_title": "NeuroShield Guard",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_start"
    }
  ],
  "web_accessible_resources": [
    {
      "resources": ["blocked.html", "blocked.js"],
      "matches": ["<all_urls>"]
    }
  ],
  "options_ui": {
    "page": "options.html",
    "open_in_tab": false
  },
  "icons": {
    "16": "icons/icon16.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  }
}`;

  const handleDownloadZip = async () => {
    setIsDownloading(true);
    try {
      const zip = new JSZip();
      
      // Fetch files from /extension or /public/extension
      const files = [
        { path: 'manifest.json', url: '/extension/manifest.json' },
        { path: 'background.js', url: '/extension/background.js' },
        { path: 'content.js', url: '/extension/content.js' },
        { path: 'blocked.html', url: '/extension/blocked.html' },
        { path: 'blocked.js', url: '/extension/blocked.js' },
        { path: 'popup.html', url: '/extension/popup.html' },
        { path: 'popup.js', url: '/extension/popup.js' },
        { path: 'options.html', url: '/extension/options.html' },
        { path: 'options.js', url: '/extension/options.js' },
        { path: 'icons/icon16.png', url: '/extension/icons/icon16.png' },
        { path: 'icons/icon48.png', url: '/extension/icons/icon48.png' },
        { path: 'icons/icon128.png', url: '/extension/icons/icon128.png' },
      ];

      for (const f of files) {
        try {
          const res = await fetch(f.url);
          if (res.ok) {
            if (f.path.endsWith('.png')) {
              const blob = await res.blob();
              zip.file(f.path, blob);
            } else {
              let text = await res.text();
              // Dynamically configure downloaded extension with the active server origin
              if (typeof window !== 'undefined' && window.location && window.location.origin && window.location.origin !== 'null') {
                text = text.replace(/http:\/\/localhost:3000/g, window.location.origin);
              }
              zip.file(f.path, text);
            }
          } else if (f.path === 'manifest.json') {
            zip.file('manifest.json', manifestContent);
          }
        } catch (e) {
          console.warn(`Failed to fetch ${f.path}, using fallback`);
        }
      }

      // Generate zip
      const content = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(content);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'neuroshield-guard-extension.zip';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 5000);
    } catch (err) {
      console.error('Failed to create extension zip:', err);
    } finally {
      setIsDownloading(false);
    }
  };

  const copyChromeUrl = () => {
    navigator.clipboard.writeText('chrome://extensions');
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 3000);
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden"
        >
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-slate-800 bg-slate-950/60">
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-sky-500/10 border border-sky-500/30 rounded-xl text-sky-400">
                <Chrome className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  NeuroShield Guard Chrome Extension
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                    Manifest V3
                  </span>
                </h3>
                <p className="text-xs text-slate-400">
                  Real-time proactive protection against phishing, deceptive QR codes, and malicious links.
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Body */}
          <div className="p-6 space-y-6 max-h-[70vh] overflow-y-auto">
            {/* Quick Summary Card */}
            <div className="p-4 rounded-xl bg-gradient-to-r from-sky-950/30 to-indigo-950/30 border border-sky-800/40 flex items-start gap-4">
              <ShieldCheck className="w-6 h-6 text-sky-400 shrink-0 mt-0.5" />
              <div className="text-xs space-y-1">
                <div className="font-bold text-slate-200">How the Extension Protects You:</div>
                <div className="text-slate-400 leading-relaxed">
                  The extension acts as a zero-friction client to your <strong>NeuroShield Core</strong> intelligence backend. When you hover over links, paste SMS text, or encounter credential forms, it inspects risk and warns you <em>before</em> dangerous actions occur.
                </div>
              </div>
            </div>

            {/* Step-by-Step Installation */}
            <div className="space-y-3">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                Installation in 3 Simple Steps:
              </h4>

              {/* Step 1 */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-3">
                <div className="w-6 h-6 rounded-full bg-sky-500/20 text-sky-400 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">
                  1
                </div>
                <div className="text-xs flex-1">
                  <div className="font-bold text-slate-200">Download and Extract Extension Archive</div>
                  <div className="text-slate-400 mt-0.5">
                    Click the download button below to get the pre-packaged <code>neuroshield-guard-extension.zip</code> and extract it to any folder on your computer.
                  </div>
                </div>
              </div>

              {/* Step 2 */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-3">
                <div className="w-6 h-6 rounded-full bg-sky-500/20 text-sky-400 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">
                  2
                </div>
                <div className="text-xs flex-1">
                  <div className="font-bold text-slate-200">Open Chrome Extensions Manager</div>
                  <div className="text-slate-400 mt-0.5 flex items-center gap-2 flex-wrap">
                    <span>Navigate to</span>
                    <code className="px-2 py-0.5 bg-slate-900 rounded border border-slate-700 text-sky-300 font-mono">
                      chrome://extensions
                    </code>
                    <button
                      onClick={copyChromeUrl}
                      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-[11px] flex items-center gap-1 cursor-pointer"
                    >
                      {copiedUrl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      {copiedUrl ? 'Copied' : 'Copy'}
                    </button>
                    <span>and switch on <strong>Developer mode</strong> (top right toggle).</span>
                  </div>
                </div>
              </div>

              {/* Step 3 */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-3">
                <div className="w-6 h-6 rounded-full bg-sky-500/20 text-sky-400 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">
                  3
                </div>
                <div className="text-xs flex-1">
                  <div className="font-bold text-slate-200">Click &quot;Load unpacked&quot; and Select Folder</div>
                  <div className="text-slate-400 mt-0.5">
                    Click <strong>Load unpacked</strong> button on the top left, choose the extracted folder, and the NeuroShield shield icon will immediately activate in your Chrome toolbar!
                  </div>
                </div>
              </div>
            </div>

            {/* Privacy Guarantee Note */}
            <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800/80 text-[11px] text-slate-400">
              <strong className="text-slate-300">Privacy & Data Minimization: </strong>
              The extension requests only <code>activeTab</code> and <code>storage</code>. It does not monitor personal browsing history, read private keystrokes, or exfiltrate sensitive files.
            </div>
          </div>

          {/* Footer Action */}
          <div className="p-6 border-t border-slate-800 bg-slate-950/80 flex flex-wrap items-center justify-between gap-3">
            <div className="text-xs text-slate-400 font-mono">
              Ready for immediate deployment
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={onClose}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-lg border border-slate-700 transition cursor-pointer"
              >
                Close
              </button>
              <button
                onClick={handleDownloadZip}
                disabled={isDownloading}
                className="px-5 py-2.5 bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-sky-950/50 transition flex items-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {downloadSuccess ? (
                  <>
                    <Check className="w-4 h-4 text-white" />
                    Downloaded!
                  </>
                ) : isDownloading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    Packaging Extension...
                  </>
                ) : (
                  <>
                    <Download className="w-4 h-4" />
                    Download Extension ZIP
                  </>
                )}
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
