import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Shield, ShieldAlert, Cpu, Search, Filter } from 'lucide-react';

const mockAlerts = [
  { id: 'INC-2024-0891', threat: 'Spear Phishing', score: 98, source: 'invoice-secure@paypal-update.com', user: 'cfo@company.com', status: 'Quarantined', date: '10 mins ago' },
  { id: 'INC-2024-0890', threat: 'Credential Harvester', score: 95, source: 'http://login.microsoftonline.verification-doc.com', user: 'sales-team@company.com', status: 'Active', date: '25 mins ago' },
  { id: 'INC-2024-0889', threat: 'CEO Fraud (BEC)', score: 88, source: 'ceo.name@gmail.com', user: 'finance-ap@company.com', status: 'Investigating', date: '1 hr ago' },
  { id: 'INC-2024-0888', threat: 'Malicious Attachment', score: 91, source: 'hr-benefits@external-vendor.net', user: 'all-employees@company.com', status: 'Resolved', date: '3 hrs ago' },
  { id: 'INC-2024-0887', threat: 'SMS Crypto Scam', score: 75, source: '+1 (555) 019-2834', user: 'm.smith (Mobile)', status: 'Active', date: '5 hrs ago' },
  { id: 'INC-2024-0886', threat: 'Suspicious Login Link', score: 60, source: 'support@slack-verify.net', user: 'dev-team', status: 'Resolved', date: '12 hrs ago' },
];

export function Alerts() {
  return (
    <div className="flex flex-col space-y-6 h-full">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-2xl font-mono text-cyber-text tracking-tight mb-1">INCIDENT RESPONSE</h2>
          <p className="text-cyber-muted text-sm">Manage and prioritize active security alerts and threats.</p>
        </div>
        <div className="flex space-x-2">
          <Button variant="outline" size="sm" className="font-mono text-xs"><Filter className="w-4 h-4 mr-2" /> FILTER</Button>
          <Button variant="default" size="sm" className="font-mono text-xs"><Shield className="w-4 h-4 mr-2" /> AUTO-REMEDIATE ALL</Button>
        </div>
      </div>

      <Card className="flex-1 flex flex-col min-h-0">
        <CardHeader className="flex flex-row items-center justify-between pb-2 border-b border-cyber-border">
          <div className="flex items-center">
            <ShieldAlert className="w-5 h-5 text-cyber-red mr-2" />
            <CardTitle className="text-sm">ACTIVE ALERTS KANBAN / LIST</CardTitle>
          </div>
          <div className="relative group">
            <input 
              type="text" 
              placeholder="Search INC-ID or Source..." 
              className="bg-cyber-bg/50 border border-cyber-border rounded-md py-1 pl-3 pr-8 text-xs font-mono focus:outline-none focus:border-cyber-blue text-cyber-text w-48 transition-all"
            />
            <Search className="w-3 h-3 absolute right-3 py-1 top-1.5 text-cyber-muted" />
          </div>
        </CardHeader>
        <CardContent className="flex-1 overflow-auto p-0">
          <table className="w-full text-sm text-left whitespace-nowrap">
            <thead className="text-xs font-mono text-cyber-muted border-b border-cyber-border bg-cyber-panel/50 sticky top-0 z-10">
              <tr>
                <th className="px-6 py-4 font-medium">INCIDENT ID</th>
                <th className="px-6 py-4 font-medium">THREAT TYPE</th>
                <th className="px-6 py-4 font-medium">AI RISK SCORE</th>
                <th className="px-6 py-4 font-medium">SOURCE / INDICATOR</th>
                <th className="px-6 py-4 font-medium">TARGET / USER</th>
                <th className="px-6 py-4 font-medium">STATUS</th>
                <th className="px-6 py-4 font-medium border-l border-cyber-border w-48">ACTION</th>
              </tr>
            </thead>
            <tbody className="font-mono text-xs">
              {mockAlerts.map((alert) => (
                <tr key={alert.id} className="border-b border-cyber-border/30 hover:bg-cyber-blue/5 transition-colors group">
                  <td className="px-6 py-4">
                    <span className="text-cyber-blue cursor-pointer hover:underline">{alert.id}</span>
                  </td>
                  <td className="px-6 py-4 text-cyber-text">{alert.threat}</td>
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <div className="w-16 h-1.5 bg-cyber-bg rounded-full mr-2 overflow-hidden border border-cyber-border">
                        <div 
                          className="h-full bg-cyber-red" 
                          style={{ width: `${alert.score}%`, backgroundColor: alert.score > 80 ? 'var(--color-cyber-red)' : '#f59e0b' }} 
                        />
                      </div>
                      <span className={alert.score > 80 ? 'text-cyber-red font-bold' : 'text-[#f59e0b]'}>{alert.score}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-cyber-muted truncate max-w-[200px]" title={alert.source}>{alert.source}</td>
                  <td className="px-6 py-4 text-cyber-muted">{alert.user}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 rounded text-[10px] font-bold ${
                      alert.status === 'Quarantined' ? 'bg-cyber-blue/20 text-cyber-blue' :
                      alert.status === 'Active' ? 'bg-cyber-red/20 text-cyber-red animate-pulse' :
                      alert.status === 'Investigating' ? 'bg-[#f59e0b]/20 text-[#f59e0b]' :
                      'bg-cyber-green/20 text-cyber-green'
                    }`}>
                      {alert.status.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-3 border-l border-cyber-border">
                    <div className="flex space-x-2">
                      {alert.status === 'Active' ? (
                        <Button size="sm" variant="danger" className="h-7 text-[10px]">QUARANTINE</Button>
                      ) : (
                        <Button size="sm" variant="outline" className="h-7 text-[10px]">INVESTIGATE</Button>
                      )}
                      <Button size="sm" variant="ghost" className="h-7 w-7 p-0" title="Ask AI Copilot"><Cpu className="w-3 h-3 text-cyber-blue" /></Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
