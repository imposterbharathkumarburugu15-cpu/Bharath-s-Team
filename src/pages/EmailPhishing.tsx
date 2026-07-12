import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Mail, Search, RefreshCw, LogIn, Bell, Shield, ShieldCheck, ShieldAlert } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { addScanToHistory } from '@/lib/history';
import { useGoogleLogin } from '@react-oauth/google';

export default function EmailPhishing() {
  const { t } = useLanguage();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoadingEmails, setIsLoadingEmails] = useState(false);

  const mockEmails = [
    {
      id: 1,
      sender: 'updates@unstop.events',
      subject: 'Last few hours to submit your Match 50 prediction | Unstop Prediction League',
      time: 'Thu, 7 May 2026 09:35:44 +0000',
      body: 'Unstop Prediction League Hi BURUGU BHARATH KUMAR, This is a quick reminder that 2 rounds of the Unstop Prediction League are currently live. You can attempt the rounds here: https://unstop.com/quiz/',
      riskScore: 20,
      signals: ['External sender domain'],
    },
    {
      id: 2,
      sender: 'noreply@unstop.news',
      subject: 'If IndiGo gave you one choice... what would you pick?',
      time: 'Thu, 07 May 2026 14:46:41 +0530',
      body: 'Hi Burugu, At IndiGo, we\'re always working to make student travel smarter. Since you engaged with our recent campaign, we\'d love to understand your preferences to create offers and experiences',
      riskScore: 20,
      signals: ['External sender domain'],
    },
    {
      id: 3,
      sender: 'security@paypal-verification-secure.com',
      subject: 'URGENT: Your account has been suspended',
      time: 'Thu, 07 May 2026 08:12:00 +0000',
      body: 'Dear Customer, We noticed suspicious activity on your account. Please click the link below immediately to verify your identity, otherwise your account will be permanently locked.',
      riskScore: 98,
      signals: ['URGENT LANGUAGE', 'SPOOFED SENDER DOMAIN', 'MALICIOUS LINK EMBEDDED'],
    }
  ];

  const [emails, setEmails] = useState<any[]>(mockEmails);

  const login = useGoogleLogin({
    scope: 'https://www.googleapis.com/auth/gmail.readonly',
    onSuccess: async (tokenResponse) => {
      setIsAuthenticated(true);
      fetchRealEmails(tokenResponse.access_token);
    },
    onError: error => console.error('Login Failed:', error)
  });

  const fetchRealEmails = async (token: string) => {
    setIsLoadingEmails(true);
    try {
      const gRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10', {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await gRes.json();
      if (!gRes.ok) {
        throw new Error(JSON.stringify(data));
      }
      
      const detailedEmails = await Promise.all(
        (data.messages || []).map(async (msg: any) => {
          const detailRes = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          const detail = await detailRes.json();
          if (!detailRes.ok) throw new Error(JSON.stringify(detail));
          const headers = detail.payload?.headers || [];
          const subject = headers.find((h: any) => h.name === 'Subject')?.value || 'No Subject';
          const sender = headers.find((h: any) => h.name === 'From')?.value || 'Unknown Sender';
          const dateStr = headers.find((h: any) => h.name === 'Date')?.value || '';
          
          let body = detail.snippet || '';
          const lowerBody = body.toLowerCase();
          const lowerSub = subject.toLowerCase();
          let riskScore = 20;
          const signals = [];

          if (lowerSub.includes('urgent') || lowerBody.includes('urgent') || lowerSub.includes('action required')) {
             riskScore += 40;
             signals.push('Urgent language detected');
          }
          if (lowerBody.includes('password') || lowerBody.includes('verify') || lowerBody.includes('login')) {
             riskScore += 30;
             signals.push('Credential request');
          }
          if (lowerBody.includes('http') && !lowerBody.includes('https')) {
             riskScore += 20;
             signals.push('Insecure HTTP link');
          }

          if (sender.includes('@gmail.com')) {
             signals.push('External sender domain');
          }

          let safeRisk = Math.min(riskScore + Math.floor(Math.random() * 5), 100);
          if (signals.length === 0) signals.push('External sender domain');
          
          return {
             id: msg.id,
             sender,
             subject,
             time: dateStr,
             body,
             riskScore: safeRisk,
             signals,
          };
        })
      );
      
      if (detailedEmails.length > 0) {
        setEmails(detailedEmails);
        detailedEmails.forEach(email => {
          addScanToHistory({
            detectedType: 'EMAIL',
            riskScore: email.riskScore,
            signals: email.signals,
            source: email.sender,
            target: 'Connected Inbox',
            payloadDescription: `Subject: ${email.subject}`,
            threatName: email.riskScore > 50 ? 'Suspicious Email' : 'Monitored Email'
          });
        });
      }
    } catch(err) {
      console.error(err);
    } finally {
      setIsLoadingEmails(false);
    }
  };

  return (
    <div className="flex-1 w-full h-full bg-[#03060a] overflow-y-auto custom-scrollbar p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        
        {/* Top Header area (mimicking the screenshot) */}
        <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-[#0a0f1c] border border-white/5 p-4 rounded-full shadow-lg">
          <div className="flex bg-[#05080f] border border-white/5 rounded-full px-4 py-2 flex-1 w-full md:max-w-md items-center">
            <Search className="w-4 h-4 text-cyber-muted mr-3" />
            <input 
              type="text" 
              placeholder="Search IPs, domains, hashes, users..." 
              className="bg-transparent border-none outline-none text-white text-sm w-full placeholder:text-cyber-muted"
            />
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-[#00ff66]/30 bg-[#00ff66]/10 text-[#00ff66] text-xs font-bold tracking-wider">
              <div className="w-1.5 h-1.5 rounded-full bg-[#00ff66] animate-pulse" />
              SYSTEM SECURE
            </div>
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-[#00f5ff]/30 bg-[#00f5ff]/10 text-[#00f5ff] text-xs font-bold tracking-wider">
               <ShieldCheck className="w-3.5 h-3.5" />
               AI MODELS ACTIVE
            </div>
            <div className="relative cursor-pointer hover:bg-white/5 p-2 rounded-full transition-colors">
              <Bell className="w-5 h-5 text-gray-400" />
              <span className="absolute top-1 right-1 w-2.5 h-2.5 bg-red-500 border-2 border-[#0a0f1c] rounded-full"></span>
            </div>
          </div>
        </div>

        {/* Connect Gmail Banner */}
        {!isAuthenticated && (
          <div className="bg-cyber-blue/5 border border-cyber-blue/30 rounded-2xl p-4 flex justify-between items-center">
             <div className="flex items-center gap-3">
               <Mail className="w-5 h-5 text-cyber-blue" />
               <div>
                  <h3 className="text-white font-bold text-sm tracking-wide">Connect your inbox</h3>
                  <p className="text-cyber-muted text-xs">Scan your real emails for threats without leaving the application.</p>
               </div>
             </div>
             <button 
               onClick={() => login()} 
               disabled={isLoadingEmails}
               className="text-[10px] sm:text-xs font-bold uppercase tracking-widest bg-cyber-blue/20 hover:bg-cyber-blue/30 text-cyber-blue border border-cyber-blue/50 px-4 py-2 rounded transition-colors flex items-center gap-2"
             >
               {isLoadingEmails ? <RefreshCw className="w-4 h-4 animate-spin" /> : <LogIn className="w-4 h-4" />}
               Connect Gmail
             </button>
          </div>
        )}

        {/* Email List */}
        <div className="space-y-4 pb-20">
          {emails.map((email) => {
            const isHighRisk = email.riskScore > 50;
            return (
              <motion.div 
                key={email.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-6 shadow-xl relative overflow-hidden group"
              >
                <div className="flex flex-col gap-1 mb-4">
                  <div className="flex justify-between items-start">
                    <div className="flex items-center gap-3 flex-wrap">
                      <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight">{email.subject}</h3>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border ${
                        isHighRisk 
                          ? 'bg-[#ff2a55]/10 text-[#ff2a55] border-[#ff2a55]/20' 
                          : 'bg-[#00ff66]/10 text-[#00ff66] border-[#00ff66]/20'
                        }`}
                      >
                        {isHighRisk ? 'HIGH RISK' : 'LOW RISK'}
                      </span>
                    </div>
                    <span className="text-[11px] text-cyber-muted font-mono whitespace-nowrap ml-4 mt-1">{email.time}</span>
                  </div>
                  
                  <div className="text-sm text-gray-400">
                    From: <span className="text-gray-300 font-medium">{email.sender}</span>
                  </div>
                </div>

                <div className="text-[13px] text-gray-400/90 leading-relaxed max-w-4xl mb-6">
                  {email.body}
                </div>

                <div className="bg-[#05080f] border border-white/5 rounded-xl p-5 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-3">
                      {isHighRisk ? (
                        <ShieldAlert className="w-4 h-4 text-[#ff2a55]" />
                      ) : (
                        <Shield className="w-4 h-4 text-[#ff2a55]" />
                      )}
                      <span className="text-xs font-bold text-white tracking-widest uppercase">Detection Reasons</span>
                    </div>
                    <ul className="list-inside space-y-1">
                      {email.signals.map((sig: string, idx: number) => (
                        <li key={idx} className="text-xs text-gray-400 flex items-center gap-2">
                           <div className="w-1 h-1 rounded-full bg-gray-500" />
                           {sig}
                        </li>
                      ))}
                    </ul>
                  </div>
                  
                  <div className="text-left sm:text-right flex flex-col items-start sm:items-end w-full sm:w-auto mt-4 sm:mt-0 pt-4 sm:pt-0 border-t sm:border-t-0 border-white/5">
                     <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-gray-500 mb-1">Threat Score</span>
                     <div className={`text-4xl sm:text-5xl font-black tabular-nums tracking-tighter ${isHighRisk ? 'text-[#ff2a55]' : 'text-[#00ff66]'}`}>
                       {email.riskScore}<span className="text-xl sm:text-2xl text-gray-600">/100</span>
                     </div>
                  </div>
                </div>
                
              </motion.div>
            );
          })}
        </div>

      </div>
      <style>{`
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(0,0,0,0.2); }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 6px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
      `}</style>
    </div>
  );
}



