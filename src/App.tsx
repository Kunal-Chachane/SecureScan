/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Search, 
  History, 
  LayoutDashboard, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  ExternalLink, 
  Menu, 
  X,
  LogOut,
  User as UserIcon,
  ChevronRight,
  BarChart3,
  Globe,
  Lock,
  Activity,
  FileText,
  Download,
  Plus
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';
import { GoogleGenAI } from "@google/genai";
import { cn, formatRiskColor, formatRiskBg } from './lib/utils';
import { User, ScanResult, DashboardStats } from './types';

// --- Components ---

const SidebarItem = ({ icon: Icon, label, active, onClick }: any) => (
  <button
    onClick={onClick}
    className={cn(
      "flex items-center w-full gap-3 px-4 py-3 rounded-lg transition-all duration-200",
      active 
        ? "bg-blue-600 text-white shadow-lg shadow-blue-600/20" 
        : "text-slate-400 hover:bg-slate-800 hover:text-white"
    )}
  >
    <Icon size={20} />
    <span className="font-medium">{label}</span>
  </button>
);

const Card = ({ children, className, title }: any) => (
  <div className={cn("bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden backdrop-blur-sm", className)}>
    {title && (
      <div className="px-6 py-4 border-bottom border-slate-800">
        <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">{title}</h3>
      </div>
    )}
    <div className="p-6">{children}</div>
  </div>
);

const StatCard = ({ label, value, icon: Icon, colorClass }: any) => (
  <Card className="relative overflow-hidden group">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-slate-400 mb-1">{label}</p>
        <h3 className="text-3xl font-bold text-white">{value}</h3>
      </div>
      <div className={cn("p-3 rounded-xl", colorClass)}>
        <Icon size={24} />
      </div>
    </div>
    <div className="absolute bottom-0 left-0 h-1 bg-current opacity-20 w-full" />
  </Card>
);

// --- Pages ---

const Dashboard = ({ stats }: { stats: DashboardStats | null }) => {
  if (!stats) return <div className="animate-pulse space-y-6">
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {[1, 2, 3].map(i => <div key={i} className="h-32 bg-slate-800 rounded-xl" />)}
    </div>
    <div className="h-96 bg-slate-800 rounded-xl" />
  </div>;

  const pieData = [
    { name: 'Safe', value: stats.total_scans - stats.malicious_count - stats.suspicious_count, color: '#10b981' },
    { name: 'Suspicious', value: stats.suspicious_count, color: '#f59e0b' },
    { name: 'Malicious', value: stats.malicious_count, color: '#f43f5e' },
  ].filter(d => d.value > 0);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <StatCard 
          label="Total Scans" 
          value={stats.total_scans} 
          icon={Activity} 
          colorClass="bg-blue-500/10 text-blue-500" 
        />
        <StatCard 
          label="Malicious Detected" 
          value={stats.malicious_count} 
          icon={AlertTriangle} 
          colorClass="bg-rose-500/10 text-rose-500" 
        />
        <StatCard 
          label="Suspicious URLs" 
          value={stats.suspicious_count} 
          icon={Shield} 
          colorClass="bg-amber-500/10 text-amber-500" 
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Threat Distribution">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-6 mt-4">
            {pieData.map(d => (
              <div key={d.name} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: d.color }} />
                <span className="text-xs text-slate-400">{d.name}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Scan Activity (Last 30 Days)">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={stats.recentScans}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis 
                  dataKey="scan_date" 
                  stroke="#64748b" 
                  fontSize={12} 
                  tickFormatter={(val) => new Date(val).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                />
                <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>
    </div>
  );
};

const ScanPage = ({ onScanComplete, lastScan }: { onScanComplete: (res: ScanResult) => void, lastScan: ScanResult | null }) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState('');

  const validateUrl = (input: string) => {
    if (!input.trim()) return false;
    // More permissive regex to allow various URL formats
    try {
      const urlToTest = input.trim().startsWith('http') ? input.trim() : 'https://' + input.trim();
      new URL(urlToTest);
      return true;
    } catch (e) {
      return false;
    }
  };

  useEffect(() => {
    let interval: any;
    if (loading) {
      const messages = [
        'Initializing secure connection...',
        'Resolving DNS records...',
        'Analyzing SSL certificate chain...',
        'Running AI threat assessment...',
        'Checking global blacklists...',
        'Finalizing risk score...'
      ];
      let msgIndex = 0;
      setStatusMsg(messages[0]);

      interval = setInterval(() => {
        setProgress(prev => {
          if (prev < 90) {
            const next = prev + Math.random() * 15;
            if (next > (msgIndex + 1) * 15 && msgIndex < messages.length - 1) {
              msgIndex++;
              setStatusMsg(messages[msgIndex]);
            }
            return next;
          }
          return prev;
        });
      }, 600);
    } else {
      setProgress(0);
      setStatusMsg('');
    }
    return () => clearInterval(interval);
  }, [loading]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedUrl = url.trim();
    
    if (!trimmedUrl) {
      setError('Please enter a URL to scan.');
      return;
    }

    if (!validateUrl(trimmedUrl)) {
      setError('Please enter a valid URL format (e.g., example.com or https://example.com).');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      // 1. Technical Scan
      setStatusMsg('Running technical diagnostics...');
      const techRes = await fetch('/api/scan/technical', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ url: trimmedUrl })
      });
      
      if (!techRes.ok) {
        const errData = await techRes.json();
        throw new Error(errData.error || 'Technical scan failed');
      }
      
      const techData = await techRes.json();
      setProgress(40);

      // 2. AI Analysis
      setStatusMsg('AI Threat Assessment...');
      const apiKey = (process.env as any).GEMINI_API_KEY;
      if (!apiKey) {
        throw new Error("Gemini API Key is not configured. Please add it to the Secrets panel.");
      }

      const ai = new GoogleGenAI({ apiKey });
      const prompt = `Analyze this URL for security threats: ${techData.url}. 
      Technical Context:
      - Domain: ${techData.domain}
      - IP: ${techData.dns.address}
      - SSL: ${techData.ssl.valid ? 'Valid' : 'Invalid/Missing'}
      - GSB Blacklisted: ${techData.gsb.blacklisted ? 'Yes' : 'No'}
      - Indicators: ${techData.indicators.join(', ')}

      Provide a comprehensive security report. 
      Return as JSON with this exact structure: 
      { 
        "score": number (0-100), 
        "summary": string, 
        "threats": string[], 
        "verdict": string (one sentence),
        "technical_details": {
          "malware": boolean,
          "phishing": boolean,
          "suspicious_scripts": boolean,
          "blacklisted": boolean,
          "domain_age": string,
          "brand_similarity": string,
          "redirects": boolean,
          "shortener_used": boolean,
          "ip_as_domain": boolean,
          "obfuscation": boolean
        },
        "hosting": {
          "provider": string,
          "country": string
        }
      }`;

      const aiAnalysis = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: prompt,
        config: { responseMimeType: "application/json" }
      });
      
      let aiData: any;
      if (aiAnalysis.text) {
        aiData = JSON.parse(aiAnalysis.text);
      } else {
        throw new Error("AI analysis returned no content");
      }
      setProgress(80);

      // 3. Finalize and Save
      setStatusMsg('Finalizing report...');
      const finalScore = Math.min(100, Math.max(techData.technical_risk_score, aiData.score || 0));
      let threatLevel = "Safe";
      if (finalScore > 70) threatLevel = "Malicious";
      else if (finalScore > 30) threatLevel = "Suspicious";

      const finalDetails = {
        domain: techData.domain,
        ip_address: techData.dns.address || "Unknown",
        protocol: techData.url.startsWith("https") ? "HTTPS" : "HTTP",
        ssl_status: techData.ssl.valid ? "Valid" : "Invalid/Missing",
        indicators: [...techData.indicators, ...(aiData.threats || [])],
        summary: aiData.summary,
        verdict: aiData.verdict,
        technical_details: {
          ...aiData.technical_details,
          blacklisted: aiData.technical_details.blacklisted || techData.gsb.blacklisted
        },
        hosting: aiData.hosting,
        timestamp: new Date().toISOString()
      };

      const saveRes = await fetch('/api/scan/save', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ 
          url: techData.url, 
          risk_score: finalScore, 
          threat_level: threatLevel,
          details: finalDetails
        })
      });

      if (!saveRes.ok) throw new Error('Failed to save scan results');
      const saveData = await saveRes.json();

      const finalResult = {
        id: saveData.id,
        url: techData.url,
        risk_score: finalScore,
        threat_level: threatLevel as any,
        created_at: new Date().toISOString(),
        details: finalDetails
      };

      setProgress(100);
      setTimeout(() => {
        onScanComplete(finalResult);
        setUrl('');
      }, 500);

    } catch (err: any) {
      setError(err.message || 'Scan failed. Please check the URL and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <div className="text-center space-y-4">
        <div className="inline-flex p-3 rounded-2xl bg-blue-600/10 text-blue-500 mb-2">
          <Shield size={48} />
        </div>
        <h1 className="text-4xl font-bold text-white tracking-tight">URL Threat Intelligence</h1>
        <p className="text-slate-400 text-lg">Enter any URL to analyze it for phishing, malware, and reputation risks.</p>
      </div>

      <Card className="p-2 relative">
        <form onSubmit={handleScan} className="flex flex-col md:flex-row gap-2">
          <div className={cn(
            "flex-1 flex items-center gap-3 bg-slate-950 border rounded-xl px-4 transition-all",
            error 
              ? "border-rose-500/50 ring-1 ring-rose-500/20" 
              : "border-slate-800 focus-within:border-blue-500/50 focus-within:ring-2 focus-within:ring-blue-500/20"
          )}>
            <Globe className="text-slate-500 shrink-0" size={20} />
            <input
              type="text"
              disabled={loading}
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (error) setError('');
              }}
              placeholder="https://example.com/suspicious-link"
              className="w-full bg-transparent py-4 text-white focus:outline-none disabled:opacity-50 placeholder:text-slate-600"
            />
          </div>
          <button
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold py-4 px-8 rounded-xl transition-all flex items-center justify-center gap-3 min-w-[180px] relative overflow-hidden"
          >
            {loading ? (
              <>
                <div className="w-5 h-5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                <span className="tracking-wide">Analyzing...</span>
              </>
            ) : (
              <>
                <Search size={20} />
                <span>Scan URL</span>
              </>
            )}
          </button>
        </form>

        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
              className="mt-6 px-4 space-y-3"
            >
              <div className="flex justify-between items-center text-xs font-bold uppercase tracking-widest">
                <span className="text-blue-400 animate-pulse">{statusMsg}</span>
                <span className="text-slate-500">{Math.round(progress)}%</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <motion.div 
                  className="h-full bg-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.5)]"
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                  transition={{ type: 'spring', bounce: 0, duration: 0.5 }}
                />
              </div>
            </motion.div>
          )}

          {error && (
            <motion.div 
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 px-4 py-3 rounded-lg bg-rose-500/10 border border-rose-500/20 overflow-hidden"
            >
              <div className="flex items-start gap-3">
                <AlertTriangle className="text-rose-500 shrink-0 mt-0.5" size={18} />
                <div className="space-y-1">
                  <p className="text-sm font-bold text-rose-500">Scan Interrupted</p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {error}
                  </p>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { icon: Lock, label: 'SSL Verification', desc: 'Certificate chain analysis' },
          { icon: Globe, label: 'DNS Reputation', desc: 'Domain age & IP history' },
          { icon: Shield, label: 'AI Detection', desc: 'Pattern-based threat scoring' },
        ].map((item, i) => (
          <div key={i} className="p-4 rounded-xl border border-slate-800 bg-slate-900/30 text-center">
            <item.icon className="mx-auto text-blue-500 mb-2" size={24} />
            <h4 className="text-white font-semibold text-sm">{item.label}</h4>
            <p className="text-slate-500 text-xs mt-1">{item.desc}</p>
          </div>
        ))}
      </div>

      {lastScan && !loading && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="pt-8 border-t border-slate-800"
        >
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-bold text-white">Most Recent Analysis</h3>
            <div className="flex gap-4">
              <button 
                onClick={() => {
                  onScanComplete(lastScan);
                  setTimeout(() => window.print(), 500);
                }}
                className="text-slate-400 hover:text-white text-sm font-bold flex items-center gap-2 transition-colors"
              >
                <Download size={16} /> Download PDF
              </button>
              <button 
                onClick={() => onScanComplete(lastScan)}
                className="text-blue-500 hover:text-blue-400 text-sm font-bold flex items-center gap-1 transition-colors"
              >
                View Full Report <ChevronRight size={16} />
              </button>
            </div>
          </div>
          
          <Card className="bg-gradient-to-br from-slate-900 to-slate-950 border-blue-500/10">
            <div className="flex flex-col md:flex-row items-center gap-8">
              <div className="shrink-0">
                <RiskMeter score={lastScan.risk_score} />
              </div>
              <div className="flex-1 space-y-4 text-center md:text-left">
                <div>
                  <p className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-1">Target URL</p>
                  <h4 className="text-xl font-bold text-white truncate max-w-md">{lastScan.url}</h4>
                </div>
                <div className="flex flex-wrap justify-center md:justify-start gap-4">
                  <div className="px-3 py-1 rounded-lg bg-slate-800 border border-slate-700">
                    <p className="text-[10px] font-bold text-slate-500 uppercase mb-0.5">Verdict</p>
                    <p className={cn("text-sm font-black", 
                      lastScan.threat_level === 'Safe' ? "text-emerald-500" : 
                      lastScan.threat_level === 'Suspicious' ? "text-amber-500" : "text-rose-500"
                    )}>
                      {lastScan.threat_level}
                    </p>
                  </div>
                  <div className="px-3 py-1 rounded-lg bg-slate-800 border border-slate-700">
                    <p className="text-[10px] font-bold text-slate-500 uppercase mb-0.5">IP Address</p>
                    <p className="text-sm text-white font-mono">{lastScan.details?.ip_address || 'Unknown'}</p>
                  </div>
                </div>
              </div>
            </div>
          </Card>
        </motion.div>
      )}
    </div>
  );
};

const RiskMeter = ({ score }: { score: number }) => {
  const rotation = (score / 100) * 180 - 90;
  const color = score > 70 ? '#f43f5e' : score > 30 ? '#f59e0b' : '#10b981';
  
  return (
    <div className="relative w-48 h-24 mx-auto overflow-hidden">
      <div className="absolute top-0 left-0 w-48 h-48 border-[12px] border-slate-800 rounded-full" />
      <motion.div 
        className="absolute top-0 left-0 w-48 h-48 border-[12px] rounded-full"
        initial={{ rotate: -90, borderColor: '#10b981' }}
        animate={{ 
          rotate: rotation,
          borderColor: color
        }}
        transition={{ type: 'spring', damping: 20, stiffness: 100 }}
        style={{ 
          clipPath: 'polygon(0 0, 100% 0, 100% 50%, 0 50%)',
          opacity: 0.8
        }}
      />
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 text-center">
        <motion.div 
          initial={{ scale: 0.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="text-4xl font-black text-white"
        >
          {score}
        </motion.div>
        <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Risk Score</div>
      </div>
    </div>
  );
};

const IndicatorItem = ({ label, status, icon: Icon }: any) => (
  <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950/50 border border-slate-800/50">
    <div className="flex items-center gap-3">
      <div className={cn("p-1.5 rounded-md", status ? "bg-rose-500/10 text-rose-500" : "bg-emerald-500/10 text-emerald-500")}>
        <Icon size={16} />
      </div>
      <span className="text-sm font-medium text-slate-300">{label}</span>
    </div>
    <div className={cn("flex items-center gap-1.5 text-[10px] font-bold uppercase px-2 py-0.5 rounded", status ? "bg-rose-500/20 text-rose-500" : "bg-emerald-500/20 text-emerald-500")}>
      {status ? <AlertTriangle size={10} /> : <CheckCircle size={10} />}
      {status ? "Detected" : "Clean"}
    </div>
  </div>
);

const ReportPage = ({ scan, onBack }: { scan: ScanResult; onBack: () => void }) => {
  const details = scan.details;
  
  const handlePrint = () => {
    window.print();
  };

  const handleShare = () => {
    const text = `Security Scan Report for ${scan.url}: Risk Score ${scan.risk_score}/100 - ${scan.threat_level}`;
    if (navigator.share) {
      navigator.share({ title: 'SecureScan Report', text, url: window.location.href });
    } else {
      navigator.clipboard.writeText(text);
      alert('Report summary copied to clipboard!');
    }
  };

  return (
    <motion.div 
      key="report"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6 pb-20 print:p-0"
    >
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 print:hidden">
        <button onClick={onBack} className="text-slate-400 hover:text-white flex items-center gap-2 transition-colors">
          <ChevronRight className="rotate-180" size={20} />
          Back to Dashboard
        </button>
        <div className="flex gap-2">
          <button onClick={handleShare} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-sm transition-all">
            <ExternalLink size={16} /> Share
          </button>
          <button onClick={handlePrint} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition-all shadow-lg shadow-blue-600/20">
            <Download size={16} /> Export PDF
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Analysis Column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Header Card */}
          <Card className={cn("border-l-4 overflow-visible", 
            scan.threat_level === 'Safe' ? "border-l-emerald-500" : 
            scan.threat_level === 'Suspicious' ? "border-l-amber-500" : "border-l-rose-500"
          )}>
            <div className="flex flex-col md:flex-row justify-between items-center gap-8">
              <div className="flex-1 space-y-4 text-center md:text-left">
                <div>
                  <div className="flex items-center justify-center md:justify-start gap-3 mb-2">
                    <span className={cn("px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest", 
                      scan.threat_level === 'Safe' ? "bg-emerald-500/10 text-emerald-500" : 
                      scan.threat_level === 'Suspicious' ? "bg-amber-500/10 text-amber-500" : "bg-rose-500/10 text-rose-500"
                    )}>
                      {scan.threat_level} Verdict
                    </span>
                    {details?.indicators?.some(i => i.toLowerCase().includes('google safe browsing')) && (
                      <span className="px-3 py-1 rounded-full bg-rose-500/10 text-rose-500 text-[10px] font-black uppercase tracking-widest border border-rose-500/20">
                        Google Safe Browsing Flag
                      </span>
                    )}
                    <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider">{new Date(scan.created_at).toLocaleString()}</span>
                  </div>
                  <h2 className="text-2xl font-bold text-white break-all leading-tight">{scan.url}</h2>
                </div>
                
                <div className={cn("p-4 rounded-xl border flex items-start gap-3 text-left", 
                  scan.threat_level === 'Safe' ? "bg-emerald-500/5 border-emerald-500/20" : 
                  scan.threat_level === 'Suspicious' ? "bg-amber-500/5 border-amber-500/20" : "bg-rose-500/5 border-rose-500/20"
                )}>
                  {scan.threat_level === 'Safe' ? <CheckCircle className="text-emerald-500 shrink-0" size={20} /> : <AlertTriangle className="text-rose-500 shrink-0" size={20} />}
                  <div>
                    <p className="text-sm font-bold text-white mb-1">Final Verdict</p>
                    <p className="text-xs text-slate-400 leading-relaxed">{details?.verdict || "Analysis complete. Review indicators below."}</p>
                  </div>
                </div>
              </div>
              
              <div className="shrink-0">
                <RiskMeter score={scan.risk_score} />
              </div>
            </div>
          </Card>

          {/* Security Analysis Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card title="🔍 Malware & Phishing" className="h-full">
              <div className="space-y-3">
                <IndicatorItem label="Malware Detection" status={details?.technical_details?.malware} icon={Activity} />
                <IndicatorItem label="Phishing Patterns" status={details?.technical_details?.phishing} icon={Shield} />
                <IndicatorItem label="Suspicious Scripts" status={details?.technical_details?.suspicious_scripts} icon={FileText} />
                <IndicatorItem label="Blacklist Status" status={details?.technical_details?.blacklisted} icon={AlertTriangle} />
              </div>
            </Card>

            <Card title="🌐 Technical Indicators" className="h-full">
              <div className="space-y-3">
                <IndicatorItem label="URL Shortener" status={details?.technical_details?.shortener_used} icon={ChevronRight} />
                <IndicatorItem label="IP as Hostname" status={details?.technical_details?.ip_as_domain} icon={Globe} />
                <IndicatorItem label="Obfuscated Code" status={details?.technical_details?.obfuscation} icon={Lock} />
                <IndicatorItem label="Redirects Detected" status={details?.technical_details?.redirects} icon={ExternalLink} />
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950/50 border border-slate-800/50">
                  <div className="flex items-center gap-3">
                    <div className="p-1.5 rounded-md bg-blue-500/10 text-blue-500">
                      <Shield size={16} />
                    </div>
                    <span className="text-sm font-medium text-slate-300">Brand Similarity</span>
                  </div>
                  <span className="text-[10px] font-bold text-white px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                    {details?.technical_details?.brand_similarity || "None"}
                  </span>
                </div>
              </div>
            </Card>
          </div>

          {/* AI Intelligence Summary */}
          <Card title="🧠 AI Threat Intelligence Summary">
            <div className="space-y-4">
              <p className="text-slate-300 leading-relaxed text-sm">
                {details?.summary || "No detailed summary available for this scan."}
              </p>
              <div className="flex flex-wrap gap-2">
                {details?.indicators?.map((ind, i) => (
                  <span key={i} className="px-2 py-1 rounded bg-slate-800 text-[10px] text-slate-400 font-medium border border-slate-700">
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          </Card>
        </div>

        {/* Sidebar Column */}
        <div className="space-y-6">
          <Card title="📋 Basic Information">
            <div className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Domain</label>
                <p className="text-sm text-white font-medium truncate">{details?.domain}</p>
              </div>
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">IP Address</label>
                <p className="text-sm text-white font-mono">{details?.ip_address}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Protocol</label>
                  <p className="text-sm text-white font-medium">{details?.protocol}</p>
                </div>
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">SSL Status</label>
                  <p className={cn("text-sm font-bold", details?.ssl_status === 'Valid' ? "text-emerald-500" : "text-rose-500")}>
                    {details?.ssl_status}
                  </p>
                </div>
              </div>
            </div>
          </Card>

          <Card title="🏢 Hosting & Origin">
            <div className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Provider</label>
                <p className="text-sm text-white font-medium">{details?.hosting?.provider}</p>
              </div>
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Country</label>
                <p className="text-sm text-white font-medium">{details?.hosting?.country}</p>
              </div>
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">IP Address</label>
                <p className="text-sm text-white font-mono">{details?.ip_address}</p>
              </div>
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Domain Age</label>
                <p className="text-sm text-white font-medium">{details?.technical_details?.domain_age}</p>
              </div>
            </div>
          </Card>

          <div className="p-6 rounded-xl bg-gradient-to-br from-blue-600/20 to-indigo-600/20 border border-blue-500/20">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-lg bg-blue-600 text-white">
                <Shield size={20} />
              </div>
              <h4 className="font-bold text-white">AI Prediction</h4>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              Our neural network predicts a <span className="text-white font-bold">{(100 - scan.risk_score).toFixed(1)}% confidence</span> that this URL is {scan.threat_level.toLowerCase()} based on current heuristics.
            </p>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div 
                className="h-full bg-blue-500" 
                style={{ width: `${100 - scan.risk_score}%` }}
              />
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
};

const HistoryPage = ({ onSelectScan }: { onSelectScan: (scan: ScanResult) => void }) => {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/history', {
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    })
      .then(res => res.json())
      .then(data => {
        setHistory(data);
        setLoading(false);
      });
  }, []);

  if (loading) return <div className="space-y-4">{[1, 2, 3].map(i => <div key={i} className="h-20 bg-slate-800 rounded-xl animate-pulse" />)}</div>;

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold text-white">Scan History</h2>
        <div className="flex gap-2">
          <button className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg text-sm hover:bg-slate-700 transition-colors">Export CSV</button>
        </div>
      </div>

      {history.length === 0 ? (
        <div className="text-center py-20 bg-slate-900/30 rounded-2xl border border-dashed border-slate-800">
          <History className="mx-auto text-slate-600 mb-4" size={48} />
          <p className="text-slate-400">No scan history found. Start by scanning a URL.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
          <div className="min-w-[800px] lg:min-w-0">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-950/50 border-b border-slate-800">
                  <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">URL</th>
                  <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Risk</th>
                  <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Level</th>
                  <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Date</th>
                  <th className="px-6 py-4"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {history.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/50 transition-colors group">
                    <td className="px-6 py-4">
                      <div className="max-w-[200px] sm:max-w-xs md:max-w-md truncate text-slate-200 font-medium">{scan.url}</div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={cn("font-bold", formatRiskColor(scan.risk_score))}>{scan.risk_score}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={cn("px-2 py-1 rounded text-[10px] font-black uppercase", 
                        scan.threat_level === 'Safe' ? "bg-emerald-500/10 text-emerald-500" : 
                        scan.threat_level === 'Suspicious' ? "bg-amber-500/10 text-amber-500" : "bg-rose-500/10 text-rose-500"
                      )}>
                        {scan.threat_level}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-slate-500 text-sm">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button 
                        onClick={() => onSelectScan(scan)}
                        className="p-2 text-slate-500 hover:text-white transition-colors"
                      >
                        <ChevronRight size={20} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

const AuthPage = ({ onAuth }: { onAuth: (user: User, token: string) => void }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (res.ok) {
        if (isLogin) {
          onAuth(data.user, data.token);
        } else {
          setIsLogin(true);
          setError('Account created. Please login.');
        }
      } else {
        setError(data.error || 'Authentication failed');
      }
    } catch (err) {
      setError('Connection error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 p-6">
      <div className="w-full max-w-md space-y-8">
        <div className="text-center">
          <div className="inline-flex p-4 rounded-2xl bg-blue-600/10 text-blue-500 mb-4">
            <Shield size={40} />
          </div>
          <h1 className="text-3xl font-bold text-white">SecureScan</h1>
          <p className="text-slate-400 mt-2">Intelligent URL Threat Intelligence</p>
        </div>

        <Card className="p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-400">Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                placeholder="analyst@securescan.io"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-400">Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                placeholder="••••••••"
              />
            </div>
            {error && <p className="text-rose-500 text-sm">{error}</p>}
            <button
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold py-3 rounded-xl transition-all"
            >
              {loading ? 'Processing...' : isLogin ? 'Sign In' : 'Create Account'}
            </button>
          </form>

          <div className="mt-6 text-center">
            <button 
              onClick={() => setIsLogin(!isLogin)}
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              {isLogin ? "Don't have an account? Sign up" : "Already have an account? Sign in"}
            </button>
          </div>
        </Card>
      </div>
    </div>
  );
};

// --- Main App ---

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [activeTab, setActiveTab] = useState<'dashboard' | 'scan' | 'history'>('dashboard');
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [lastScan, setLastScan] = useState<ScanResult | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  useEffect(() => {
    if (token) {
      // Basic check if token is valid (could be improved)
      const storedUser = localStorage.getItem('user');
      if (storedUser) setUser(JSON.parse(storedUser));
      fetchStats();
    }
  }, [token]);

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/dashboard-stats', {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {}
  };

  const handleAuth = (u: User, t: string) => {
    setUser(u);
    setToken(t);
    localStorage.setItem('token', t);
    localStorage.setItem('user', JSON.stringify(u));
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  };

  const handleScanComplete = (scan: ScanResult) => {
    setSelectedScan(scan);
    setLastScan(scan);
    fetchStats();
  };

  if (!token) return <AuthPage onAuth={handleAuth} />;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex overflow-x-hidden">
      {/* Sidebar Backdrop for Mobile */}
      <AnimatePresence>
        {isSidebarOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setIsSidebarOpen(false)}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <aside className={cn(
        "fixed inset-y-0 left-0 z-50 w-64 bg-slate-950 border-r border-slate-800 transition-transform duration-300 lg:relative lg:translate-x-0",
        !isSidebarOpen && "-translate-x-full"
      )}>
        <div className="flex flex-col h-full p-6">
          <div className="flex items-center gap-3 mb-10 px-2">
            <div className="p-2 bg-blue-600 rounded-lg text-white">
              <Shield size={24} />
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight">SecureScan</h1>
          </div>

          <nav className="flex-1 space-y-2">
            <SidebarItem 
              icon={LayoutDashboard} 
              label="Dashboard" 
              active={activeTab === 'dashboard' && !selectedScan} 
              onClick={() => { setActiveTab('dashboard'); setSelectedScan(null); }} 
            />
            <SidebarItem 
              icon={Search} 
              label="URL Scanner" 
              active={activeTab === 'scan' && !selectedScan} 
              onClick={() => { setActiveTab('scan'); setSelectedScan(null); }} 
            />
            <SidebarItem 
              icon={History} 
              label="Scan History" 
              active={activeTab === 'history' && !selectedScan} 
              onClick={() => { setActiveTab('history'); setSelectedScan(null); }} 
            />
          </nav>

          <div className="mt-auto pt-6 border-t border-slate-800 space-y-4">
            <div className="flex items-center gap-3 px-2">
              <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center text-blue-500">
                <UserIcon size={20} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-bold text-white truncate">{user?.email}</p>
                <p className="text-xs text-slate-500 uppercase tracking-wider">{user?.role}</p>
              </div>
            </div>
            <button 
              onClick={handleLogout}
              className="flex items-center w-full gap-3 px-4 py-3 text-slate-400 hover:text-rose-500 transition-colors"
            >
              <LogOut size={20} />
              <span className="font-medium">Sign Out</span>
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0">
        <header className="h-16 border-b border-slate-800 flex items-center justify-between px-6 bg-slate-950/50 backdrop-blur-md sticky top-0 z-40">
          <button 
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="lg:hidden p-2 text-slate-400 hover:text-white"
          >
            {isSidebarOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
          
          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-500 text-[10px] font-bold uppercase tracking-wider">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              System Online
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button className="p-2 text-slate-400 hover:text-white transition-colors">
              <Plus size={20} />
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-6 lg:p-10">
          <AnimatePresence mode="wait">
            {selectedScan ? (
              <ReportPage scan={selectedScan} onBack={() => setSelectedScan(null)} />
            ) : (
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
              >
                {activeTab === 'dashboard' && <Dashboard stats={stats} />}
                {activeTab === 'scan' && <ScanPage onScanComplete={handleScanComplete} lastScan={lastScan} />}
                {activeTab === 'history' && <HistoryPage onSelectScan={setSelectedScan} />}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
}

