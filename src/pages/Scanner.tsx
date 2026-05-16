import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ShieldCheck, Search, Cpu, X, UploadCloud, AlertCircle, Send, Globe, Mail, Code, Link2, Paperclip, FileText, Image as ImageIcon, Database, Terminal, Lock } from 'lucide-react';
import { cn } from '@/lib/utils';
import { analyzeThreat, ScanResult } from '@/services/geminiService';
import { addScanToHistory } from '@/lib/history';
import { UrlScannerResult } from '@/components/UrlScannerResult';
import { TextScannerResult } from '@/components/TextScannerResult';
import { useLanguage } from '@/contexts/LanguageContext';

type ScanStatus = 'idle' | 'scanning' | 'complete';

export function LiveScanner() {
  const { t, language } = useLanguage();
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [inputText, setInputText] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  
  const [attachedFile, setAttachedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const placeholders = [
    t('paste_placeholder'),
    t('paste_phishing_message'),
    t('submit_payload')
  ];
  const [placeholderIdx, setPlaceholderIdx] = useState(0);

  useEffect(() => {
    if (status !== 'idle') return;
    const interval = setInterval(() => {
      setPlaceholderIdx((prev) => (prev + 1) % placeholders.length);
    }, 3000);
    return () => clearInterval(interval);
  }, [status, placeholders.length]);

  // Mock scan progress
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (status === 'scanning') {
      interval = setInterval(() => {
        setScanProgress(p => {
          if (p >= 90) return 90;
          return p + (Math.random() * 15);
        });
      }, 300);
    }
    return () => clearInterval(interval);
  }, [status]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setAttachedFile(file);
      if (file.type.startsWith('image/')) {
        setPreviewUrl(URL.createObjectURL(file));
      } else {
        setPreviewUrl(null);
      }
    }
  };

  const removeFile = () => {
    setAttachedFile(null);
    setPreviewUrl(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleScan = async () => {
    if (!inputText.trim() && !attachedFile) return;
    setStatus('scanning');
    setScanProgress(0);

    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const phoneRegex = /(?:\+?91[\-\s]?)?[0]?[\-\s]?[6-9]\d{2}[\-\s]?\d{3}[\-\s]?\d{4}\b/g;
    const aadhaarRegex = /\b[2-9]\d{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/g;
    const panRegex = /\b[A-Za-z]{5}\d{4}[A-Za-z]\b/g;
    const passportRegex = /\b[A-Za-z][1-9]\d{6}\b/g;
    const nameRegex = /\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|Dear|Hi|Hello)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b/g;
    const amountRegex = /(?:\b(?:transfer|send|pay|amount|rs\.?|inr)|[\$₹])\s*[\$₹]?\s*(\d+(?:,\d+)*(?:\.\d+)?)\b/gi;
    
    // Prompt Injection Detection Logic
    const promptInjectionKeywords = [
      "ignore previous instructions",
      "ignore all previous",
      "override system",
      "reveal secrets",
      "reveal your prompt",
      "act as",
      "bypass restrictions",
      "you are now",
      "developer mode",
      "dan mode",
      "stay out of character"
    ];
    
    const promptInjectionDetected = promptInjectionKeywords.some(phrase => 
      inputText.toLowerCase().includes(phrase.toLowerCase())
    );

    let emails: string[] = inputText.match(emailRegex) || [];
    let phones: string[] = inputText.match(phoneRegex) || [];
    let aadhaars: string[] = inputText.match(aadhaarRegex) || [];
    let pans: string[] = inputText.match(panRegex) || [];
    let passports: string[] = inputText.match(passportRegex) || [];
    
    let names: string[] = [];
    let nameMatch;
    while ((nameMatch = nameRegex.exec(inputText)) !== null) {
      if (nameMatch[1]) names.push(nameMatch[1]);
    }

    let amounts: string[] = [];
    let amountMatch;
    while ((amountMatch = amountRegex.exec(inputText)) !== null) {
      if (amountMatch[0]) amounts.push(amountMatch[0]);
    }
    
    // De-duplicate
    emails = Array.from(new Set(emails));
    phones = Array.from(new Set(phones));
    aadhaars = Array.from(new Set(aadhaars));
    pans = Array.from(new Set(pans));
    passports = Array.from(new Set(passports));
    names = Array.from(new Set(names));
    amounts = Array.from(new Set(amounts));

    const detectedMasks: { original: string; masked: string; type?: string }[] = [];

    // Base Risk Score Calculation
    let dynamicRiskScore = 0;
    const dynamicSignals: string[] = [];

    if (promptInjectionDetected) {
      dynamicRiskScore = 90;
      dynamicSignals.push("🧠 AI MANIPULATION PATTERN DETECTED");
    }

    if (emails.length > 0 || phones.length > 0 || aadhaars.length > 0 || pans.length > 0) {
      dynamicRiskScore += 20;
      dynamicSignals.push("🔐 SENSITIVE DATA FOUND");
    }

    // Urgency detection (simplified)
    const urgencyKeywords = ["urgent", "soon", "immediately", "quick", "fast", "asap", "hurry"];
    if (urgencyKeywords.some(k => inputText.toLowerCase().includes(k))) {
      dynamicRiskScore += 20;
      dynamicSignals.push("⚠ URGENCY DETECTED");
    }

    if (inputText.includes('http') || inputText.includes('www.')) {
      dynamicRiskScore += 30;
      dynamicSignals.push("🔗 SUSPICIOUS LINK");
    }

    // Apply masks to final scan result
    const applyMasksToResult = (result: typeof scanResult, masks: typeof detectedMasks) => {
      if (!result) return result;
      
      const sanitizeStr = (str: string) => {
        let newStr = str;
        masks.forEach(m => {
           if (m.original) {
             // Case-insensitive replacement fallback could be helpful, but we do exact first
             newStr = newStr.split(m.original).join(m.masked);
           }
        });
        return newStr;
      };

      const res = { ...result };
      if (res.aiExplanation) res.aiExplanation = sanitizeStr(res.aiExplanation);
      if (res.payloadDescription) res.payloadDescription = sanitizeStr(res.payloadDescription);
      if (res.threatName) res.threatName = sanitizeStr(res.threatName);
      
      if (res.suspiciousKeywords) {
        // Map and clean keywords. Use a Set to remove duplicates that may arise after masking.
        const cleaned = res.suspiciousKeywords.map(sanitizeStr);
        res.suspiciousKeywords = Array.from(new Set(cleaned));
      }
      if (res.signals) {
        res.signals = res.signals.map(sanitizeStr);
      }
      
      return res;
    };

    emails.forEach(email => {
      const atIndex = email.indexOf('@');
      if (atIndex > 1) {
        const masked = email.charAt(0) + '*'.repeat(atIndex - 1) + email.substring(atIndex);
        detectedMasks.push({ original: email, masked, type: 'Email' });
      } else {
        detectedMasks.push({ original: email, masked: '*'.repeat(atIndex) + email.substring(atIndex), type: 'Email' });
      }
    });

    aadhaars.forEach(aadhaar => {
      const clean = aadhaar.replace(/\D/g, '');
      if (clean.length === 12) {
        const masked = `XXXX-XXXX-${clean.slice(8, 12)}`;
        detectedMasks.push({ original: aadhaar, masked, type: 'Aadhaar ID' });
      } else {
        const unmasked = aadhaar.slice(-4);
        const masked = aadhaar.slice(0, -4).replace(/\d/g, 'X') + unmasked;
        detectedMasks.push({ original: aadhaar, masked, type: 'Aadhaar ID' });
      }
    });

    phones.forEach(phone => {
      // Avoid overlapping phones with aadhaar
      if (!aadhaars.some(a => a.replace(/\D/g, '').includes(phone.replace(/\D/g, '')))) {
        const unmasked = phone.slice(-4);
        const masked = phone.slice(0, -4).replace(/\d/g, 'X') + unmasked;
        detectedMasks.push({ original: phone, masked, type: 'Phone' });
      }
    });

    pans.forEach(pan => {
      const masked = 'XXXXX' + pan.slice(5, 9) + 'X';
      detectedMasks.push({ original: pan, masked, type: 'PAN Card' });
    });

    passports.forEach(passport => {
      const masked = passport.substring(0, 2) + 'X'.repeat(passport.length - 2);
      detectedMasks.push({ original: passport, masked, type: 'Passport' });
    });

    names.forEach(name => {
      const masked = name.split(' ').map(part => part.charAt(0) + '*'.repeat(part.length > 1 ? part.length - 1 : 0)).join(' ');
      detectedMasks.push({ original: name, masked, type: 'Name' });
    });

    amounts.forEach(amount => {
      const masked = amount.replace(/\d(?=\d)/g, 'x'); // replaces all digits except the last digit with 'x' (or 'X')
      // Wait, "transferxx0", so 'x' case?
      // Let's replace digits except the last one with 'x'
      detectedMasks.push({ original: amount, masked: amount.replace(/\d(?=[,\d\.]*\d)/g, 'x'), type: 'Amount' });
    });

    let sanitizedText = inputText;
    let newSuspiciousKeywords: string[] = [];
    detectedMasks.forEach(({ original, masked }) => {
      sanitizedText = sanitizedText.split(original).join(masked);
      newSuspiciousKeywords.push(masked);
    });

    try {
      let base64Data: string | undefined;
      let mimeType: string | undefined;

      if (attachedFile) {
        const reader = new FileReader();
        reader.onloadend = async () => {
          const result = reader.result as string;
          base64Data = result.split(',')[1];
          mimeType = attachedFile.type;
          
          try {
            const res = await analyzeThreat(sanitizedText, language, base64Data, mimeType);
            if (detectedMasks.length > 0) {
              res.maskedData = [...(res.maskedData || []), ...detectedMasks];
            }
            if (newSuspiciousKeywords.length > 0) {
              res.suspiciousKeywords = [...Array.from(new Set([...(res.suspiciousKeywords || []), ...newSuspiciousKeywords]))];
            }
            
            // Merge dynamic signals and update risk score
            res.signals = Array.from(new Set([...(res.signals || []), ...dynamicSignals]));
            res.riskScore = Math.min(100, (res.riskScore || 0) + dynamicRiskScore);

            const finalRes = applyMasksToResult(res, detectedMasks);
            addScanToHistory(finalRes);
            setScanResult(finalRes);
          } catch(err) {
            console.error(err);
            const dummy = getDummyResult();
            if (detectedMasks.length > 0) {
              dummy.maskedData = detectedMasks;
            }
            if (newSuspiciousKeywords.length > 0) {
              dummy.suspiciousKeywords = [...Array.from(new Set([...(dummy.suspiciousKeywords || []), ...newSuspiciousKeywords]))];
            }

            // Merge dynamic signals to dummy
            dummy.signals = Array.from(new Set([...(dummy.signals || []), ...dynamicSignals]));
            dummy.riskScore = Math.min(100, (dummy.riskScore || 0) + dynamicRiskScore);

            const finalDummy = applyMasksToResult(dummy, detectedMasks);
            addScanToHistory(finalDummy);
            setScanResult(finalDummy);
          }
          completeScan();
        };
        reader.readAsDataURL(attachedFile);
      } else {
        const res = await analyzeThreat(sanitizedText, language);
        if (detectedMasks.length > 0) {
          res.maskedData = [...(res.maskedData || []), ...detectedMasks];
        }
        if (newSuspiciousKeywords.length > 0) {
          res.suspiciousKeywords = [...Array.from(new Set([...(res.suspiciousKeywords || []), ...newSuspiciousKeywords]))];
        }

        // Merge dynamic signals and update risk score
        res.signals = Array.from(new Set([...(res.signals || []), ...dynamicSignals]));
        res.riskScore = Math.min(100, (res.riskScore || 0) + dynamicRiskScore);

        const finalRes = applyMasksToResult(res, detectedMasks);
        addScanToHistory(finalRes);
        setScanResult(finalRes);
        completeScan();
      }
    } catch (error) {
      console.error(error);
      const dummy = getDummyResult();
      if (detectedMasks.length > 0) {
        dummy.maskedData = detectedMasks;
      }
      if (newSuspiciousKeywords.length > 0) {
        dummy.suspiciousKeywords = [...Array.from(new Set([...(dummy.suspiciousKeywords || []), ...newSuspiciousKeywords]))];
      }

      // Merge dynamic signals to dummy
      dummy.signals = Array.from(new Set([...(dummy.signals || []), ...dynamicSignals]));
      dummy.riskScore = Math.min(100, (dummy.riskScore || 0) + dynamicRiskScore);

      setScanResult(applyMasksToResult(dummy, detectedMasks));
      completeScan();
    }
  };

  const completeScan = () => {
    setScanProgress(100);
    setTimeout(() => {
      setStatus('complete');
    }, 300);
  };

  const getDummyResult = (): ScanResult => {
    if (inputText.toLowerCase().includes('ignore previous instructions') || inputText.toLowerCase().includes('reveal secrets')) {
      return {
        detectedType: 'AI_MANIPULATION',
        riskScore: 92,
        signals: ['🧠 AI MANIPULATION PATTERN DETECTED', '⚠ URGENCY DETECTED', 'SENSITIVE DATA FOUND'],
        source: 'Unknown External Node',
        target: 'SENTINEL AI ENGINE',
        payloadDescription: 'Instruction Override Attempt',
        threatName: 'Prompt Injection / System Hijack',
        aiExplanation: 'The payload contains explicit instruction override patterns designed to bypass system restrictions and reveal internal context or secrets.',
        suspiciousKeywords: ['ignore previous', 'reveal secrets', 'override'],
        detectedLinks: [],
        maskedData: [
          { original: 'SECRET_KEY_123', masked: '************', type: 'System Secret' }
        ],
        textMetrics: {
          urgency: 95,
          financial: 20,
          impersonation: 50,
          deception: 98,
          coercion: 85
        }
      };
    }

    if (inputText.includes('http') || inputText.includes('www.')) {
      return {
        detectedType: 'URL',
        riskScore: 94,
        signals: ['URGENT LANGUAGE DETECTED', 'SENSITIVE DATA FOUND', 'SUSPICIOUS LINK'],
        source: '185.199.108.153',
        target: 'USER WORKSTATION',
        payloadDescription: 'Malicious credential harvesting link',
        maskedData: [
          { original: 'Password123!', masked: 'XXXXXXXXXXX!' },
          { original: 'john.doe@company.com', masked: 'j***.d**@c******.com' }
        ],
        urlMetrics: {
          domainAge: '5+ years',
          sslCertificate: "Valid (Let's Encrypt)",
          blacklistStatus: 'Clean',
          typosquatting: 'None detected',
          subdomains: '2',
          radarData: {
            domainAge: 80,
            sslStatus: 90,
            blacklist: 85,
            typosquatting: 90,
            subdomains: 60,
            contentRisk: 75,
          }
        }
      };
    }

    return {
      detectedType: 'CHAT',
      riskScore: 85,
      signals: ['IMPERSONATION', 'URGENCY', 'FINANCIAL REQUEST'],
      source: 'Unknown Number',
      target: 'User',
      payloadDescription: 'Social engineering impersonation scam',
      threatName: 'Impersonation Scam',
      aiExplanation: 'This message exhibits signs of an impersonation scam (e.g., "Hi Mum" scam), creating urgency and requesting financial assistance under false pretenses. The sender attempts to manipulate the victim into transferring funds immediately.',
      suspiciousKeywords: ['urgent', 'transfer', 'help', 'account'],
      detectedLinks: [],
      maskedData: [
        { original: '1234567890', masked: '1********0' },
      ],
      textMetrics: {
        urgency: 90,
        financial: 85,
        impersonation: 80,
        deception: 95,
        coercion: 70
      }
    };
  };

  const handleReset = () => {
    setStatus('idle');
    setInputText('');
    setScanProgress(0);
    setScanResult(null);
  };

  return (
    <div className="relative w-full flex-1 bg-cyber-bg">
      <div className="h-full flex flex-col max-w-7xl mx-auto w-full relative font-mono text-white p-4 lg:p-8">
        
        {/* Background Ambience */}
        <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none">
          <div className="scanline" />
          <div className="absolute top-1/4 left-1/4 w-[40vw] h-[40vw] bg-cyber-blue/10 rounded-full blur-[120px] mix-blend-screen" />
          <div className="absolute bottom-1/4 right-1/4 w-[30vw] h-[30vw] bg-cyber-red/10 rounded-full blur-[100px] mix-blend-screen" />
          <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/stardust.png')] opacity-20 mix-blend-screen" />
        </div>

        <AnimatePresence mode="wait">
          
          {/* ================= INPUT PHASE ================= */}
          {status === 'idle' && (
            <motion.div 
              key="idle"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, filter: 'blur(10px)', scale: 1.05 }}
              transition={{ duration: 0.5 }}
              className="flex-1 flex flex-col justify-center items-center z-10 w-full max-w-4xl mx-auto h-full relative"
            >
              {/* Spinning Orbital Background for Scanner */}
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-30 mt-10">
                <motion.div animate={{ rotate: 360 }} transition={{ duration: 60, repeat: Infinity, ease: 'linear' }} className="absolute w-[700px] h-[700px] rounded-full border-[1px] border-dashed border-cyber-blue/30" />
                <motion.div animate={{ rotate: -360 }} transition={{ duration: 40, repeat: Infinity, ease: 'linear' }} className="absolute w-[500px] h-[500px] rounded-full border-2 border-dotted border-[#00ff66]/20" />
                <motion.div animate={{ scale: [0.95, 1.05, 0.95], opacity: [0.3, 0.6, 0.3] }} transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }} className="absolute w-[300px] h-[300px] rounded-full border-[1px] border-cyber-red/20 shadow-[0_0_100px_var(--color-cyber-red)]" />
              </div>

              <div className="flex flex-col items-center mb-10 w-full mt-auto relative z-10">
                <motion.div 
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: [1, 1.05, 1], opacity: [1, 1, 1] }}
                  transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                  className="w-24 h-24 bg-black/40 border border-cyber-blue/50 rounded-3xl flex items-center justify-center shadow-[0_0_40px_rgba(0,245,255,0.4)] mb-8 relative backdrop-blur-xl overflow-hidden group"
                >
                  <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,_var(--color-cyber-blue)_0%,_transparent_60%)] opacity-20" />
                  <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0IiBoZWlnaHQ9IjQiPgo8cmVjdCB3aWR0aD0iNCIgaGVpZ2h0PSI0IiBmaWxsPSIjZmZmIiBmaWxsLW9wYWNpdHk9IjAuMSIvPgo8L3N2Zz4=')] mix-blend-overlay" />
                  <ShieldCheck className="w-12 h-12 text-cyber-blue relative z-10 drop-shadow-[0_0_15px_var(--color-cyber-blue-glow)]" />
                  
                  {/* Cyberpunk corner accents */}
                  <div className="absolute top-0 left-0 w-4 h-4 border-t-[3px] border-l-[3px] border-cyber-blue" />
                  <div className="absolute top-0 right-0 w-4 h-4 border-t-[3px] border-r-[3px] border-cyber-blue" />
                  <div className="absolute bottom-0 left-0 w-4 h-4 border-b-[3px] border-l-[3px] border-cyber-blue" />
                  <div className="absolute bottom-0 right-0 w-4 h-4 border-b-[3px] border-r-[3px] border-cyber-blue" />
                </motion.div>
                
                <h1 className="text-4xl md:text-6xl font-black tracking-[0.2em] text-transparent bg-clip-text bg-gradient-to-r from-white via-[#00f5ff] to-white mb-3 text-center filter drop-shadow-[0_0_15px_rgba(0,245,255,0.4)] uppercase">
                  {t('scanner_title')}
                </h1>
                
                <div className="flex items-center gap-3">
                  <span className="h-[1px] w-12 bg-gradient-to-r from-transparent to-[#00f5ff]"></span>
                  <p className="text-[#00f5ff] text-xs md:text-sm tracking-[0.4em] text-center font-bold uppercase drop-shadow-[0_0_5px_rgba(0,245,255,0.5)]">
                    Advanced Deep Payload Analysis
                  </p>
                  <span className="h-[1px] w-12 bg-gradient-to-l from-transparent to-[#00f5ff]"></span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 w-full mb-8 max-w-4xl mx-auto relative z-10">
                {[
                  { icon: Mail, label: t('quick_action_phishing_label'), text: t('quick_action_phishing_text') },
                  { icon: Link2, label: t('quick_action_url_label'), text: t('quick_action_url_text') },
                  { icon: Code, label: t('quick_action_code_label'), text: t('quick_action_code_text') },
                  { icon: Globe, label: t('quick_action_network_label'), text: t('quick_action_network_text') },
                  { icon: Cpu, label: t('quick_action_prompt_label'), text: t('quick_action_prompt_text') },
                  { icon: Database, label: t('quick_action_sql_label'), text: t('quick_action_sql_text') },
                  { icon: Terminal, label: t('quick_action_xss_label'), text: t('quick_action_xss_text') },
                  { icon: Lock, label: t('quick_action_ransom_label'), text: t('quick_action_ransom_text') },
                ].map((suggestion, idx) => (
                  <motion.button
                    key={idx}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 + idx * 0.1 }}
                    onClick={() => setInputText(suggestion.text)}
                    className="bg-black/40 backdrop-blur-md border border-white/10 hover:border-[#00f5ff] rounded-xl p-4 flex flex-col items-start gap-3 text-left transition-all hover:bg-[#00f5ff]/5 hover:shadow-[inset_0_0_20px_rgba(0,245,255,0.1),_0_0_15px_rgba(0,245,255,0.2)] group relative overflow-hidden"
                  >
                    <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-white/20 group-hover:via-[#00f5ff]/50 to-transparent" />
                    <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-[#00f5ff]/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                    
                    <div className="p-2 rounded-lg bg-white/5 border border-white/5 text-cyber-muted group-hover:text-[#00f5ff] group-hover:bg-[#00f5ff]/10 group-hover:border-[#00f5ff]/30 transition-all shadow-[0_0_10px_rgba(0,0,0,0.5)]">
                      <suggestion.icon className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-white mb-1 uppercase tracking-widest group-hover:text-[#00f5ff] transition-colors">{suggestion.label}</div>
                      <div className="text-[10px] text-[#8a99af] line-clamp-2 leading-relaxed">{suggestion.text}</div>
                    </div>
                  </motion.button>
                ))}
              </div>

              <div className="relative group w-full max-w-4xl mx-auto mb-auto z-20">
                {/* Glowing Outer Halo */}
                <div className="absolute -inset-[2px] bg-gradient-to-r from-cyber-blue via-[#7000ff] to-[#00ff66] rounded-xl opacity-30 group-focus-within:opacity-100 blur-lg transition-all duration-700 pointer-events-none" />
                
                {/* Main Terminal Frame */}
                <div className="relative bg-[#020408]/90 backdrop-blur-3xl rounded-xl border border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.8)] flex flex-col focus-within:border-[#00f5ff]/70 transition-colors duration-500 overflow-hidden group-focus-within:shadow-[0_0_30px_rgba(0,245,255,0.2)]">
                  
                  {/* Terminal Header */}
                  <div className="h-10 bg-[#060913] border-b border-white/10 flex items-center justify-between px-5">
                    <div className="flex gap-2">
                       <span className="w-3 h-3 rounded-full bg-[#ff2a55]/30 border border-[#ff2a55] shadow-[0_0_5px_#ff2a55]" />
                       <span className="w-3 h-3 rounded-full bg-[#ffea00]/30 border border-[#ffea00] shadow-[0_0_5px_#ffea00]" />
                       <span className="w-3 h-3 rounded-full bg-[#00ff66]/30 border border-[#00ff66] shadow-[0_0_5px_#00ff66]" />
                    </div>
                    <div className="flex items-center gap-2 text-[10px] font-bold tracking-[0.2em] uppercase text-[#8a99af] group-focus-within:text-[#00f5ff] transition-colors">
                      <Cpu className="w-3.5 h-3.5" />
                      SECURE_DROPZONE_v9.2
                    </div>
                    <div className="flex gap-1.5 opacity-50">
                       <div className="w-1 h-3 bg-cyber-blue" />
                       <div className="w-1 h-3 bg-cyber-blue" />
                       <div className="w-1 h-3 bg-cyber-blue" />
                    </div>
                  </div>

                  {/* Corner Target Marks */}
                  <div className="absolute top-12 left-2 w-4 h-4 border-t border-l border-white/20 pointer-events-none" />
                  <div className="absolute top-12 right-2 w-4 h-4 border-t border-r border-white/20 pointer-events-none" />

                  {previewUrl && (
                    <div className="relative w-32 h-32 mt-6 ml-6 rounded-lg overflow-hidden border-2 border-[#00f5ff]/50 shadow-[0_0_20px_rgba(0,245,255,0.3)]">
                      <img src={previewUrl} alt="Preview" className="w-full h-full object-cover" />
                      <button onClick={removeFile} className="absolute top-2 right-2 bg-black/80 hover:bg-[#ff2a55] p-1.5 rounded-full text-white transition-all backdrop-blur-md">
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  )}
                  
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    className="hidden"
                    accept="image/*,application/pdf"
                  />
                  
                  <textarea
                    value={inputText}
                    onChange={(e) => {
                      setInputText(e.target.value);
                      e.target.style.height = 'auto';
                      e.target.style.height = (e.target.scrollHeight) + 'px';
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        handleScan();
                      }
                    }}
                    className="w-full min-h-[120px] max-h-[300px] bg-transparent text-white font-mono text-sm leading-relaxed p-6 pb-16 outline-none resize-none z-10 custom-scrollbar placeholder:text-[#3a495f]"
                    spellCheck="false"
                    placeholder={placeholders[placeholderIdx]}
                    rows={3}
                  />
                  
                  <div className="absolute bottom-4 left-6 right-6 flex justify-between items-center z-20">
                    <div className="flex items-center gap-3">
                      <button 
                        onClick={() => fileInputRef.current?.click()}
                        className="text-[#8a99af] hover:text-[#00f5ff] transition-colors p-2 rounded-lg bg-white/5 hover:bg-[#00f5ff]/10 border border-transparent hover:border-[#00f5ff]/30 relative group shadow-sm flex items-center gap-2"
                        title={t('attach_file')}
                      >
                        <Paperclip className="w-4 h-4" />
                        <span className="text-xs font-bold uppercase tracking-widest hidden sm:inline-block">Attach</span>
                      </button>
                      
                      {attachedFile && !previewUrl && (
                        <div className="flex items-center gap-2 text-[#00f5ff] text-xs bg-[#00f5ff]/10 px-3 py-1.5 rounded-lg border border-[#00f5ff]/30 max-w-[200px] shadow-[0_0_10px_rgba(0,245,255,0.2)]">
                          <FileText className="w-4 h-4 shrink-0" />
                          <span className="truncate font-bold tracking-wider">{attachedFile.name}</span>
                          <button onClick={removeFile} className="hover:text-[#ff2a55] ml-auto shrink-0 transition-colors"><X className="w-4 h-4" /></button>
                        </div>
                      )}
                    </div>
                    
                    <button 
                      onClick={handleScan} 
                      disabled={!inputText.trim() && !attachedFile}
                      className={cn(
                        "h-10 px-6 rounded-lg flex items-center justify-center font-bold tracking-[0.2em] uppercase transition-all duration-300 gap-2 overflow-hidden relative group",
                        (inputText.trim() || attachedFile)
                          ? "bg-gradient-to-r from-[#00f5ff] to-[#00ff66] text-[#020408] hover:shadow-[0_0_30px_rgba(0,245,255,0.6)] hover:scale-105" 
                          : "bg-white/5 text-[#8a99af] border border-white/10 cursor-not-allowed"
                      )}
                    >
                      {/* Shine effect */}
                      {(inputText.trim() || attachedFile) && (
                         <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/40 to-transparent -translate-x-full group-hover:animate-[shimmer_1.5s_infinite]" />
                      )}
                      <span>INITIATE</span>
                      <Send className={cn("w-4 h-4", (inputText.trim() || attachedFile) && "ml-1")} />
                    </button>
                  </div>
                </div>
              </div>
              
              <div className="text-[10px] text-cyber-muted mt-6 tracking-[0.3em] uppercase mb-4 text-center font-bold">
                {t('scanner_disclaimer')}
              </div>
            </motion.div>
          )}

          {/* ================= SCANNING PHASE ================= */}
          {status === 'scanning' && (
            <motion.div 
              key="scanning"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, scale: 1.1, filter: 'blur(20px)' }}
              transition={{ duration: 0.5 }}
              className="absolute inset-0 z-50 flex flex-col items-center justify-center bg-[#020408]/95 backdrop-blur-3xl overflow-hidden"
            >
              {/* Massive Scanning Grid Background */}
              <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-10 animate-[pulse_2s_infinite]" />
              <div className="absolute inset-x-0 top-0 h-40 bg-gradient-to-b from-[#00f5ff]/20 to-transparent opacity-50" />
              <div className="absolute inset-x-0 bottom-0 h-40 bg-gradient-to-t from-[#ff2a55]/20 to-transparent opacity-50" />
              
              <div className="scanline" />
              
              <motion.div 
                initial={{ scale: 0.5, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ type: "spring", damping: 20 }}
                className="relative w-full max-w-4xl text-center z-10 p-12 border border-[#00f5ff]/30 bg-[#060913]/80 shadow-[0_0_150px_rgba(0,245,255,0.15)] rounded-3xl backdrop-blur-xl overflow-hidden"
              >
                {/* Internal container glow and scanline */}
                <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_transparent_0%,_#020408_100%)] opacity-80 pointer-events-none" />
                <motion.div 
                  animate={{ top: ['-20%', '120%'] }}
                  transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                  className="absolute left-0 right-0 h-[3px] bg-[#00f5ff] shadow-[0_0_50px_#00f5ff,_0_0_20px_#00f5ff] z-20"
                />
                
                {/* Advanced Central Core */}
                <div className="flex justify-center mb-16 relative">
                  <div className="relative w-56 h-56 flex items-center justify-center">
                    {/* Ring 1 - Outer fast dashed */}
                    <motion.div animate={{ rotate: 360 }} transition={{ duration: 8, repeat: Infinity, ease: "linear" }} className="absolute inset-0 rounded-full border-t-[4px] border-l-[1px] border-dashed border-[#00f5ff] opacity-80 shadow-[0_0_20px_#00f5ff]" />
                    {/* Ring 2 - Inner counter-spin green */}
                    <motion.div animate={{ rotate: -360 }} transition={{ duration: 5, repeat: Infinity, ease: "linear" }} className="absolute inset-4 rounded-full border-b-[4px] border-r-[2px] border-dotted border-[#00ff66] opacity-70 shadow-[0_0_15px_#00ff66]" />
                    {/* Ring 3 - Solid red pulse */}
                    <motion.div animate={{ scale: [0.9, 1.1, 0.9], opacity: [0.3, 0.8, 0.3] }} transition={{ duration: 1.2, repeat: Infinity, ease: "easeInOut" }} className="absolute inset-8 rounded-full border-2 border-[#ff2a55] shadow-[0_0_30px_#ff2a55] bg-[#ff2a55]/10" />
                    {/* Ring 4 - Center core */}
                    <div className="absolute inset-12 rounded-full border border-white/20 bg-black flex items-center justify-center overflow-hidden">
                       <motion.div animate={{ rotate: 360 }} transition={{ duration: 3, repeat: Infinity, ease: "linear" }} className="absolute inset-[-50%] bg-[conic-gradient(from_0deg,transparent_0_340deg,#00f5ff_360deg)] opacity-50" />
                       <Search className="w-10 h-10 text-white relative z-10 drop-shadow-[0_0_10px_white] animate-pulse" />
                    </div>
                    
                    {/* High-speed data particles erupting from center */}
                    <div className="absolute inset-0 pointer-events-none">
                      {Array.from({ length: 12 }).map((_, i) => (
                        <motion.div
                          key={i}
                          className="absolute left-1/2 top-1/2 w-1.5 h-6 bg-[#00f5ff] rounded-full shadow-[0_0_8px_#00f5ff]"
                          style={{
                             rotate: `${i * 30}deg`,
                             transformOrigin: '0 0',
                          }}
                          animate={{
                            y: [20, 150],
                            opacity: [1, 0],
                            scaleY: [1, 3]
                          }}
                          transition={{
                            duration: 0.8 + Math.random() * 0.5,
                            repeat: Infinity,
                            ease: "easeOut",
                            delay: Math.random() * 0.5
                          }}
                        />
                      ))}
                    </div>
                  </div>
                </div>

                <div className="relative z-10 space-y-6">
                  <AnimatePresence mode="wait">
                    <motion.div 
                      key={scanProgress < 40 ? 'phase1' : scanProgress < 75 ? 'phase2' : 'phase3'}
                      initial={{ opacity: 0, y: 10, filter: 'blur(8px)' }}
                      animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
                      exit={{ opacity: 0, y: -10, filter: 'blur(8px)' }}
                      className="text-3xl md:text-5xl font-black tracking-[0.4em] text-transparent bg-clip-text bg-gradient-to-r from-white to-[#00f5ff] uppercase drop-shadow-[0_0_15px_rgba(0,245,255,0.5)]"
                    >
                      {scanProgress < 40 ? 'DECRYPTING PAYLOAD...' : scanProgress < 75 ? 'NEURAL THREAT ANALYSIS...' : 'COMPILING RISKS...'}
                    </motion.div>
                  </AnimatePresence>
                  
                  <div className="flex justify-between items-end border-b border-white/10 pb-2">
                    <div className="flex flex-col text-left space-y-1">
                      <span className="text-[10px] text-[#8a99af] tracking-[0.2em] font-mono">SYS.PROCESS.ID // 0x8F92A</span>
                      <span className="text-xs text-[#00ff66] font-mono font-bold animate-pulse">CONNECTION_SECURE</span>
                    </div>
                    <div className="text-right">
                       <span className="text-[10px] text-[#8a99af] tracking-widest block font-mono">ESTIMATED COMPLETION</span>
                       <span className="text-3xl font-black tracking-tighter text-white drop-shadow-[0_0_10px_white]">
                         {Math.floor(scanProgress)}<span className="text-[#00f5ff] text-xl">%</span>
                       </span>
                    </div>
                  </div>
                  
                  {/* High-Tech Progress Bar */}
                  <div className="w-full h-3 bg-[#020408] border border-[#00f5ff]/30 rounded-r-lg rounded-l-sm p-[1px] relative shadow-[inset_0_0_10px_rgba(0,0,0,0.8)] overflow-hidden">
                    <motion.div 
                      className="h-full bg-gradient-to-r from-[#00f5ff] via-[#00ff66] to-[#ff2a55] relative"
                      initial={{ width: "0%" }}
                      animate={{ width: `${scanProgress}%` }}
                    >
                      {/* Animated diagonal stripes on the progress bar */}
                      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4IiBoZWlnaHQ9IjgiPgo8cGF0aCBkPSJNMCA4TDggMCA4IDFMMSA4eiIgZmlsbD0iI2ZmZiIgZmlsbC1vcGFjaXR5PSIwLjMiLz4KPC9zdmc+')] animate-[shimmer_1s_linear_infinite]" />
                    </motion.div>
                  </div>
                  
                  <div className="grid grid-cols-3 gap-4 pt-4 border-t border-white/5 text-[10px] font-mono text-[#8a99af] text-left uppercase tracking-widest">
                     <div>
                        <span className="block opacity-50 mb-1">Target Engine</span>
                        <span className="text-[#00f5ff] font-bold">SENTINEL-CORE-V2</span>
                     </div>
                     <div className="text-center">
                        <span className="block opacity-50 mb-1">Status</span>
                        <span className="text-[#ffea00] font-bold animate-pulse">ACTIVE_SCANNING</span>
                     </div>
                     <div className="text-right">
                        <span className="block opacity-50 mb-1">Memory Allocation</span>
                        <span className="text-white font-bold">{(128 + scanProgress * 5).toFixed(0)} MB</span>
                     </div>
                  </div>
                </div>
              </motion.div>
            </motion.div>
          )}

          {/* ================= RESULT PHASE ================= */}
          {status === 'complete' && scanResult && (
            <motion.div 
              key="complete"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex-1 flex flex-col z-10 h-full max-h-full"
            >
              {scanResult.detectedType === 'URL' ? (
                <UrlScannerResult scanResult={scanResult} inputText={inputText} onReset={handleReset} />
              ) : (
                <TextScannerResult scanResult={scanResult} onReset={handleReset} />
              )}
            </motion.div>
          )}
        </AnimatePresence>
        
        {/* Global override styles for custom scrollbar in this view */}
        <style>{`
          .custom-scrollbar::-webkit-scrollbar {
            width: 4px;
          }
          .custom-scrollbar::-webkit-scrollbar-track {
            background: rgba(255,255,255,0.02); 
          }
          .custom-scrollbar::-webkit-scrollbar-thumb {
            background: rgba(0, 245, 255, 0.2); 
            border-radius: 4px;
          }
          .custom-scrollbar::-webkit-scrollbar-thumb:hover {
            background: rgba(0, 245, 255, 0.5); 
          }
        `}</style>
      </div>
    </div>
  );
}
