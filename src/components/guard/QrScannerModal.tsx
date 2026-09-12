import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  X, 
  QrCode, 
  Upload, 
  Search, 
  CheckCircle, 
  AlertTriangle, 
  ExternalLink,
  Shield,
  ArrowRight,
  RefreshCw,
  Copy
} from 'lucide-react';
import jsQR from 'jsqr';

interface QrScannerModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanPayload: (payload: string) => void;
}

export function QrScannerModal({ isOpen, onClose, onScanPayload }: QrScannerModalProps) {
  const [extractedPayload, setExtractedPayload] = useState<string | null>(null);
  const [qrImageSrc, setQrImageSrc] = useState<string | null>(null);
  const [isDecoding, setIsDecoding] = useState(false);
  const [decodeError, setDecodeError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Pre-configured QR samples for testing
  const samplePresets = [
    {
      title: 'Phishing QR: Fake Banking Verify',
      payload: 'https://chase-security-verify.update-account.com/login?qr_auth=91837',
      desc: 'Quishing attack targeting mobile users to harvest banking credentials',
    },
    {
      title: 'Suspicious QR: Cloudflare Tunnel Lure',
      payload: 'https://security-notice-291.trycloudflare.com/verify-identity',
      desc: 'Reverse proxy tunnel bypassing email and network filters',
    },
    {
      title: 'UPI Scam: Fake Merchant Payment Request',
      payload: 'upi://pay?pa=refund-desk@okaxis&pn=Electricity%20Support&am=1.00&cu=INR&tn=Immediate%20Verification',
      desc: 'Financial lure attempting authorization under false refund pretext',
    },
    {
      title: 'Legitimate QR: Official Chase Bank',
      payload: 'https://www.chase.com/personal/banking',
      desc: 'Legitimate financial institution portal',
    },
  ];

  const handleFileUpload = (file: File) => {
    setIsDecoding(true);
    setDecodeError(null);
    setExtractedPayload(null);

    const reader = new FileReader();
    reader.onload = (e) => {
      const src = e.target?.result as string;
      setQrImageSrc(src);

      const image = new Image();
      image.onload = () => {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = image.width;
        canvas.height = image.height;

        if (ctx) {
          ctx.drawImage(image, 0, 0, image.width, image.height);
          const imageData = ctx.getImageData(0, 0, image.width, image.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'dontInvert',
          });

          if (code && code.data) {
            setExtractedPayload(code.data);
          } else {
            // If jsQR couldn't detect standard grid, provide fallback message
            setDecodeError('Could not decode a standard QR grid from this image. You can test with our sample presets below or manually enter the payload.');
          }
        }
        setIsDecoding(false);
      };
      image.onerror = () => {
        setDecodeError('Failed to load the image file.');
        setIsDecoding(false);
      };
      image.src = src;
    };
    reader.readAsDataURL(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const copyPayload = () => {
    if (extractedPayload) {
      navigator.clipboard.writeText(extractedPayload);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
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
              <div className="p-2.5 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-400">
                <QrCode className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  QR Code & Quishing Defense Scanner
                </h3>
                <p className="text-xs text-slate-400">
                  Inspect QR targets and UPI payment requests <strong>before</strong> your camera or phone opens them.
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
            {/* Upload Area */}
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-slate-700 hover:border-amber-500/50 bg-slate-950/50 hover:bg-slate-950 rounded-xl p-6 text-center cursor-pointer transition group"
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
              />
              <div className="mx-auto w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 group-hover:text-amber-400 group-hover:border-amber-500/30 transition mb-3">
                <Upload className="w-6 h-6" />
              </div>
              <div className="text-sm font-bold text-slate-200">
                Click to upload QR code image or drag & drop here
              </div>
              <div className="text-xs text-slate-500 mt-1">
                Supports PNG, JPG, WebP, SVG screenshots from posters, emails, or parking meters
              </div>
            </div>

            {/* Loading or Error */}
            {isDecoding && (
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-center text-xs text-slate-400 flex items-center justify-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin text-amber-400" />
                Decoding QR code matrix payload...
              </div>
            )}

            {decodeError && (
              <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-800/40 text-xs text-amber-300 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
                <div>{decodeError}</div>
              </div>
            )}

            {/* Extracted Payload Result */}
            {extractedPayload && (
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                    Decoded QR Target Payload
                  </span>
                  <button
                    onClick={copyPayload}
                    className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded border border-slate-800 text-[11px] flex items-center gap-1 cursor-pointer"
                  >
                    <Copy className="w-3 h-3" />
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>

                <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 font-mono text-xs text-amber-200 break-all select-all">
                  {extractedPayload}
                </div>

                <div className="text-[11px] text-slate-400">
                  <strong className="text-slate-300">Safety Hold: </strong>
                  This URL has NOT been opened on your device. Click below to run deep multi-engine intelligence on the payload first.
                </div>
              </div>
            )}

            {/* Sample Quishing Presets */}
            <div className="space-y-3 pt-2">
              <div className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                Or Test with Simulated Quishing Presets:
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {samplePresets.map((preset, idx) => (
                  <button
                    key={idx}
                    onClick={() => {
                      setExtractedPayload(preset.payload);
                      setDecodeError(null);
                    }}
                    className="p-3 rounded-lg bg-slate-950 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 text-left transition cursor-pointer group"
                  >
                    <div className="text-xs font-bold text-slate-200 group-hover:text-amber-300 flex items-center justify-between">
                      <span>{preset.title}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                      {preset.desc}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Footer Actions */}
          <div className="p-6 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-lg border border-slate-700 transition cursor-pointer"
            >
              Cancel
            </button>

            <button
              disabled={!extractedPayload}
              onClick={() => {
                if (extractedPayload) {
                  onScanPayload(extractedPayload);
                  onClose();
                }
              }}
              className="px-5 py-2.5 bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-amber-950/50 transition flex items-center gap-2 cursor-pointer disabled:opacity-40 disabled:pointer-events-none"
            >
              <Shield className="w-4 h-4" />
              Inspect Target with NeuroShield
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
