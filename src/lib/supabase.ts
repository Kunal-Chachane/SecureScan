import { createClient } from '@supabase/supabase-js';

// ──────────────────────────────────────────────────────────
// Database type definitions generated from Supabase schema
// ──────────────────────────────────────────────────────────
export type Json = string | number | boolean | null | { [key: string]: Json } | Json[];

export interface Database {
    public: {
        Tables: {
            threats: {
                Row: {
                    id: number;
                    name: string;
                    description: string | null;
                    severity: 'low' | 'medium' | 'high' | 'critical';
                    created_at: string;
                    updated_at: string;
                };
                Insert: Omit<Database['public']['Tables']['threats']['Row'], 'id' | 'created_at' | 'updated_at'>;
                Update: Partial<Database['public']['Tables']['threats']['Insert']>;
            };
            users: {
                Row: {
                    id: number;
                    username: string | null;
                    /** Stored encrypted (pgp_sym_encrypt). Always BYTEA in DB. */
                    email: string;       // decrypted value exposed to application layer
                    /** Stored encrypted (pgp_sym_encrypt). Always BYTEA in DB. */
                    api_key: string | null;
                    email_hash: string;
                    api_key_hash: string | null;
                    role: 'admin' | 'analyst' | 'viewer';
                    last_login_at: string | null;
                    created_at: string;
                    updated_at: string;
                };
                Insert: Omit<Database['public']['Tables']['users']['Row'], 'id' | 'created_at' | 'updated_at'>;
                Update: Partial<Database['public']['Tables']['users']['Insert']>;
            };
            urls: {
                Row: {
                    id: number;
                    /** Stored encrypted (pgp_sym_encrypt). Always BYTEA in DB. */
                    url: string;         // decrypted value exposed to application layer
                    url_hash: string;
                    domain: string;
                    last_scanned_at: string | null;
                    status: 'safe' | 'malicious' | 'suspicious' | 'unknown';
                    created_at: string;
                    updated_at: string;
                };
                Insert: Omit<Database['public']['Tables']['urls']['Row'], 'id' | 'created_at' | 'updated_at'>;
                Update: Partial<Database['public']['Tables']['urls']['Insert']>;
            };
            scans: {
                Row: {
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
                };
                Insert: Omit<Database['public']['Tables']['scans']['Row'], 'id' | 'created_at'>;
                Update: Partial<Database['public']['Tables']['scans']['Insert']>;
            };
            scan_results: {
                Row: {
                    id: number;
                    scan_id: number;
                    threat_type: string | null;
                    /** Stored encrypted (pgp_sym_encrypt). Always BYTEA in DB. */
                    threat_details: Json | null;  // decrypted + parsed JSON exposed to app layer
                    confidence_score: number | null;
                    scanned_content_hash: string | null;
                    created_at: string;
                };
                Insert: Omit<Database['public']['Tables']['scan_results']['Row'], 'id' | 'created_at'>;
                Update: Partial<Database['public']['Tables']['scan_results']['Insert']>;
            };
        };
        Views: {
            decrypted_scan_summary: {
                Row: {
                    scan_id: number;
                    scan_time: string;
                    status: string;
                    risk_score: number | null;
                    threat_level: string | null;
                    result_summary: string | null;
                    scanner_version: string;
                    scan_created_at: string;
                    url_id: number;
                    domain: string;
                    url_hash: string;
                    url_status: string;
                    result_id: number | null;
                    threat_type: string | null;
                    confidence_score: number | null;
                    scanned_content_hash: string | null;
                    result_created_at: string | null;
                };
            };
        };
        Functions: Record<string, never>;
        Enums: Record<string, never>;
    };
}

// ──────────────────────────────────────────────────────────
// Supabase client — typed with the Database schema above
// ──────────────────────────────────────────────────────────
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string;

if (!supabaseUrl || !supabaseAnonKey) {
    console.warn('[SecureScan] Supabase env vars missing — check VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in .env');
}

export const supabase = createClient<Database>(
    supabaseUrl || 'https://bgwtkgfpgzjtjbouqbfe.supabase.co',
    supabaseAnonKey || ''
);

// ──────────────────────────────────────────────────────────
// Convenience type aliases
// ──────────────────────────────────────────────────────────
export type Tables<T extends keyof Database['public']['Tables']> =
    Database['public']['Tables'][T]['Row'];

export type InsertTables<T extends keyof Database['public']['Tables']> =
    Database['public']['Tables'][T]['Insert'];

export type UpdateTables<T extends keyof Database['public']['Tables']> =
    Database['public']['Tables'][T]['Update'];

export type SupabaseUser = Tables<'users'>;
export type SupabaseUrl = Tables<'urls'>;
export type SupabaseScan = Tables<'scans'>;
export type SupabaseScanResult = Tables<'scan_results'>;
export type SupabaseThreat = Tables<'threats'>;
