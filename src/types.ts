// ============================================================
// EXISTING types — kept for backward compatibility with server.ts
// ============================================================

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

// ============================================================
// SUPABASE TABLE TYPES — aligned with the Supabase schema
// Encrypted fields are noted; the app layer receives decrypted values.
// ============================================================

/** Reference lookup table — threat categories */
export interface SupabaseThreat {
  id: number;
  name: string;
  description: string | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  created_at: string;
  updated_at: string;
}

/**
 * users table.
 * `email` and `api_key` are stored encrypted in Supabase (pgp_sym_encrypt).
 * This interface represents the decrypted, application-layer view.
 */
export interface SupabaseUser {
  id: number;
  username: string | null;
  email: string;          // decrypted value; DB stores BYTEA
  api_key: string | null; // decrypted value; DB stores BYTEA
  email_hash: string;     // SHA-256 hex — used for lookup, not decryptable to original
  api_key_hash: string | null;
  role: 'admin' | 'analyst' | 'viewer';
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * urls table.
 * `url` is stored encrypted in Supabase (pgp_sym_encrypt).
 * `domain` is plaintext for indexing/search.
 */
export interface SupabaseUrl {
  id: number;
  url: string;      // decrypted value; DB stores BYTEA
  url_hash: string; // SHA-256 hex — used for deduplication
  domain: string;   // plaintext
  last_scanned_at: string | null;
  status: 'safe' | 'malicious' | 'suspicious' | 'unknown';
  created_at: string;
  updated_at: string;
}

/** scans table — no sensitive columns; all plaintext */
export interface SupabaseScan {
  id: number;
  url_id: number;
  user_id: number | null;
  scan_time: string;
  scanner_version: string;
  status: 'pending' | 'completed' | 'failed';
  risk_score: number | null;
  threat_level: 'Safe' | 'Suspicious' | 'Malicious' | 'Unknown' | null;
  result_summary: string | null;
  created_at: string;
}

/**
 * scan_results table.
 * `threat_details` is stored encrypted in Supabase (pgp_sym_encrypt).
 * This interface represents the decrypted, application-layer view.
 */
export interface SupabaseScanResult {
  id: number;
  scan_id: number;
  threat_type: string | null;
  threat_details: Record<string, unknown> | null; // decrypted JSON; DB stores BYTEA
  confidence_score: number | null;
  scanned_content_hash: string | null;
  created_at: string;
}

/** Joined view — used for history / dashboard queries */
export interface FullScanRecord {
  scan: SupabaseScan;
  url: SupabaseUrl;
  results: SupabaseScanResult[];
}
