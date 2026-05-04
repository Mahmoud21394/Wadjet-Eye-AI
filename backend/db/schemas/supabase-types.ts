/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Supabase TypeScript Type Definitions
 *  backend/db/schemas/supabase-types.ts
 *
 *  Auto-generated from PostgreSQL schema (migration 001).
 *  Use with @supabase/supabase-js for full type safety.
 *
 *  Generate: npx supabase gen types typescript --local > backend/db/schemas/supabase-types.ts
 * ══════════════════════════════════════════════════════════════════
 */

export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[];

export type Database = {
  public: {
    Tables: {
      tenants: {
        Row: {
          id: string;
          name: string;
          slug: string;
          plan: string;
          max_users: number;
          max_alerts_day: number;
          api_rate_limit: number;
          mfa_required: boolean;
          allowed_ips: string[] | null;
          settings: Json;
          active: boolean;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          name: string;
          slug: string;
          plan?: string;
          max_users?: number;
          max_alerts_day?: number;
          api_rate_limit?: number;
          mfa_required?: boolean;
          allowed_ips?: string[] | null;
          settings?: Json;
          active?: boolean;
          created_at?: string;
          updated_at?: string;
        };
        Update: Partial<Database['public']['Tables']['tenants']['Insert']>;
      };
      users: {
        Row: {
          id: string;
          tenant_id: string;
          email: string;
          display_name: string | null;
          password_hash: string;
          role: 'SUPER_ADMIN' | 'ADMIN' | 'TEAM_LEAD' | 'ANALYST' | 'READ_ONLY' | 'API_USER';
          active: boolean;
          mfa_enabled: boolean;
          mfa_secret: string | null;
          mfa_backup_codes: string[] | null;
          last_login_at: string | null;
          last_login_ip: string | null;
          failed_logins: number;
          locked_until: string | null;
          password_changed_at: string | null;
          must_change_pw: boolean;
          session_data: Json;
          preferences: Json;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          tenant_id: string;
          email: string;
          display_name?: string | null;
          password_hash: string;
          role?: 'SUPER_ADMIN' | 'ADMIN' | 'TEAM_LEAD' | 'ANALYST' | 'READ_ONLY' | 'API_USER';
          active?: boolean;
          mfa_enabled?: boolean;
          mfa_secret?: string | null;
          mfa_backup_codes?: string[] | null;
          preferences?: Json;
        };
        Update: Partial<Database['public']['Tables']['users']['Insert']>;
      };
      alerts: {
        Row: {
          id: string;
          tenant_id: string;
          title: string;
          description: string | null;
          severity: 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
          status: 'open' | 'in_progress' | 'escalated' | 'closed' | 'false_positive' | 'true_positive' | 'duplicate';
          risk_score: number;
          confidence: number;
          rule_id: string | null;
          rule_name: string | null;
          detection_source: string | null;
          category: string | null;
          mitre_tactic: string | null;
          mitre_technique: string | null;
          mitre_subtechnique: string | null;
          host: string | null;
          host_ip: string | null;
          username: string | null;
          source_ip: string | null;
          dest_ip: string | null;
          process_name: string | null;
          process_hash: string | null;
          incident_id: string | null;
          cluster_id: string | null;
          parent_alert_id: string | null;
          assignee_id: string | null;
          outcome: string | null;
          event_time: string | null;
          first_seen: string;
          last_seen: string;
          ticket_created_at: string | null;
          closed_at: string | null;
          ioc_count: number;
          tags: string[];
          enriched: boolean;
          enrichment_data: Json;
          raw_event_ids: string[];
          evidence: Json;
          ai_summary: string | null;
          ai_recommended_actions: string[] | null;
          playbook_triggered: boolean;
          soar_case_id: string | null;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          tenant_id: string;
          title: string;
          description?: string | null;
          severity?: 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
          status?: 'open' | 'in_progress' | 'escalated' | 'closed' | 'false_positive' | 'true_positive' | 'duplicate';
          risk_score?: number;
          confidence?: number;
          rule_id?: string | null;
          rule_name?: string | null;
          detection_source?: string | null;
          category?: string | null;
          mitre_tactic?: string | null;
          mitre_technique?: string | null;
          host?: string | null;
          username?: string | null;
          source_ip?: string | null;
          tags?: string[];
          evidence?: Json;
        };
        Update: Partial<Database['public']['Tables']['alerts']['Insert']>;
      };
      iocs: {
        Row: {
          id: string;
          tenant_id: string;
          value: string;
          type: 'ip' | 'ipv6' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'hash_sha512' | 'email' | 'cve' | 'asn' | 'cidr' | 'filename' | 'registry' | 'mutex' | 'bitcoin_address' | 'other';
          severity: 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
          confidence: number;
          risk_score: number;
          malicious: boolean | null;
          tags: string[];
          tlp: string;
          source: string | null;
          first_seen: string;
          last_seen: string;
          expires_at: string | null;
          active: boolean;
          enrichment_data: Json;
          stix_id: string | null;
          stix_bundle_id: string | null;
          false_positive: boolean;
          fp_reported_by: string | null;
          fp_reported_at: string | null;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          tenant_id: string;
          value: string;
          type: Database['public']['Tables']['iocs']['Row']['type'];
          severity?: Database['public']['Tables']['iocs']['Row']['severity'];
          confidence?: number;
          risk_score?: number;
          malicious?: boolean | null;
          tags?: string[];
          tlp?: string;
          source?: string | null;
        };
        Update: Partial<Database['public']['Tables']['iocs']['Insert']>;
      };
      detection_rules: {
        Row: {
          id: string;
          tenant_id: string | null;
          rule_id: string;
          name: string;
          description: string | null;
          rule_type: 'sigma' | 'custom' | 'ml' | 'composite';
          severity: Database['public']['Tables']['alerts']['Row']['severity'];
          mitre_tactic: string | null;
          mitre_technique: string | null;
          logic: Json;
          sigma_yaml: string | null;
          enabled: boolean;
          threshold: number;
          false_positive_rate: number;
          true_positive_rate: number;
          trigger_count: number;
          fp_count: number;
          tp_count: number;
          last_triggered: string | null;
          last_tuned_at: string | null;
          auto_tune: boolean;
          tags: string[];
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          tenant_id?: string | null;
          rule_id: string;
          name: string;
          description?: string | null;
          rule_type?: 'sigma' | 'custom' | 'ml' | 'composite';
          severity?: Database['public']['Tables']['alerts']['Row']['severity'];
          mitre_tactic?: string | null;
          mitre_technique?: string | null;
          logic?: Json;
          sigma_yaml?: string | null;
          enabled?: boolean;
          threshold?: number;
        };
        Update: Partial<Database['public']['Tables']['detection_rules']['Insert']>;
      };
      soc_metrics: {
        Row: {
          id: string;
          tenant_id: string;
          period_start: string;
          period_end: string;
          period_type: 'hourly' | 'daily' | 'weekly' | 'monthly';
          total_alerts: number;
          open_alerts: number;
          closed_alerts: number;
          fp_alerts: number;
          tp_alerts: number;
          fp_rate: number | null;
          tp_rate: number | null;
          avg_mttd: number | null;
          avg_mttr: number | null;
          p50_mttd: number | null;
          p95_mttd: number | null;
          p50_mttr: number | null;
          p95_mttr: number | null;
          sla_met_count: number;
          sla_breached_count: number;
          sla_compliance_pct: number | null;
          total_analysts: number;
          alerts_per_analyst: number | null;
          active_cases: number;
          total_incidents: number;
          critical_incidents: number;
          top_rules: Json;
          mitre_coverage: Json;
          raw_data: Json;
          recorded_at: string;
        };
        Insert: Omit<Database['public']['Tables']['soc_metrics']['Row'], 'id'>;
        Update: Partial<Database['public']['Tables']['soc_metrics']['Insert']>;
      };
      audit_log: {
        Row: {
          id: number;
          tenant_id: string | null;
          user_id: string | null;
          user_email: string | null;
          action: string;
          resource_type: string | null;
          resource_id: string | null;
          changes: Json | null;
          ip_address: string | null;
          user_agent: string | null;
          request_id: string | null;
          status: string;
          error: string | null;
          prev_hash: string | null;
          event_hash: string | null;
          created_at: string;
        };
        Insert: Omit<Database['public']['Tables']['audit_log']['Row'], 'id' | 'created_at'>;
        Update: never; // Append-only
      };
      agent_decisions: {
        Row: {
          id: string;
          tenant_id: string;
          alert_id: string | null;
          incident_id: string | null;
          agent_type: string;
          decision: 'auto_closed' | 'auto_escalated' | 'needs_review' | 'ticket_created' | 'playbook_triggered' | 'insufficient_data';
          confidence: number | null;
          reasoning: string | null;
          actions_taken: Json;
          human_approved: boolean | null;
          approved_by: string | null;
          approved_at: string | null;
          override_reason: string | null;
          execution_ms: number | null;
          llm_model: string | null;
          prompt_tokens: number | null;
          completion_tokens: number | null;
          created_at: string;
        };
        Insert: Omit<Database['public']['Tables']['agent_decisions']['Row'], 'id' | 'created_at'>;
        Update: Pick<Database['public']['Tables']['agent_decisions']['Row'], 'human_approved' | 'approved_by' | 'approved_at' | 'override_reason'>;
      };
    };
    Views: Record<string, never>;
    Functions: Record<string, never>;
    Enums: {
      severity_level: 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
      alert_status: 'open' | 'in_progress' | 'escalated' | 'closed' | 'false_positive' | 'true_positive' | 'duplicate';
      case_status: 'open' | 'investigating' | 'contained' | 'remediated' | 'closed' | 'archived';
      user_role: 'SUPER_ADMIN' | 'ADMIN' | 'TEAM_LEAD' | 'ANALYST' | 'READ_ONLY' | 'API_USER';
      ioc_type: 'ip' | 'ipv6' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'hash_sha512' | 'email' | 'cve' | 'asn' | 'cidr' | 'filename' | 'registry' | 'mutex' | 'bitcoin_address' | 'other';
    };
  };
};

// ── Helper types ──────────────────────────────────────────────────
export type Tables<T extends keyof Database['public']['Tables']> =
  Database['public']['Tables'][T]['Row'];

export type Enums<T extends keyof Database['public']['Enums']> =
  Database['public']['Enums'][T];

// Convenience type aliases
export type Tenant         = Tables<'tenants'>;
export type User           = Tables<'users'>;
export type Alert          = Tables<'alerts'>;
export type Ioc            = Tables<'iocs'>;
export type DetectionRule  = Tables<'detection_rules'>;
export type SocMetric      = Tables<'soc_metrics'>;
export type AuditLogEntry  = Tables<'audit_log'>;
export type AgentDecision  = Tables<'agent_decisions'>;
export type SeverityLevel  = Enums<'severity_level'>;
export type AlertStatus    = Enums<'alert_status'>;
export type UserRole       = Enums<'user_role'>;
export type IocType        = Enums<'ioc_type'>;
