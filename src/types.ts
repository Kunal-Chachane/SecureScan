export interface User {
  id: number;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
}

export interface ScanResult {
  id: number;
  url: string;
  risk_score: number;
  threat_level: 'Safe' | 'Suspicious' | 'Malicious';
  created_at: string;
  details?: {
    domain: string;
    ip_address: string;
    protocol: string;
    ssl_status: string;
    indicators: string[];
    summary: string;
    verdict: string;
    technical_details: {
      malware: boolean;
      phishing: boolean;
      suspicious_scripts: boolean;
      blacklisted: boolean;
      domain_age: string;
      brand_similarity: string;
      redirects: boolean;
      shortener_used: boolean;
      ip_as_domain: boolean;
      obfuscation: boolean;
    };
    hosting: {
      provider: string;
      country: string;
    };
    timestamp: string;
  };
}

export interface DashboardStats {
  total_scans: number;
  malicious_count: number;
  suspicious_count: number;
  recentScans: Array<{
    threat_level: string;
    count: number;
    scan_date: string;
  }>;
  threatCategories: Array<{
    name: string;
    count: number;
  }>;
  riskTrends: Array<{
    date: string;
    avgRisk: number;
  }>;
  topDomains: Array<{
    domain: string;
    count: number;
  }>;
}
