// Types mirror the backend's Pydantic schemas (backend/app/schemas/schemas.py).

export type Role = "viewer" | "analyst" | "admin";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type RiskLevel = "unknown" | "none" | "low" | "medium" | "high" | "critical";
export type IncidentState = "open" | "under_investigation" | "quarantined" | "remediation_required" | "resolved";

export interface User {
  id: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
}

export interface Dataset {
  id: string;
  name: string;
  version: string;
  source: string;
  description: string;
  file_format: string;
  original_filename: string;
  size_bytes: number;
  sha256: string;
  row_count: number;
  columns: string[];
  parent_id: string | null;
  approval_status: "pending" | "approved" | "rejected";
  integrity_status: "verified" | "modified" | "unverified";
  risk_level: RiskLevel;
  quarantined: boolean;
  created_at: string;
}

export interface Finding {
  id: string;
  inspection_id: string;
  dataset_id: string;
  severity: Severity;
  method: string;
  title: string;
  confidence: number;
  explanation: string;
  evidence: Record<string, unknown> & { row_indices?: number[]; row_indices_total?: number };
  investigation_steps: string[];
  limitations: string;
  status: "open" | "acknowledged" | "dismissed";
  created_at: string;
}

export interface MethodStatus {
  method: string;
  status: "ran" | "skipped" | "error";
  reason: string;
  duration_ms: number;
  findings: number;
}

export interface Inspection {
  id: string;
  dataset_id: string;
  reference_dataset_id: string | null;
  status: string;
  risk_level: RiskLevel;
  risk_score: number;
  config: Record<string, unknown>;
  methods: MethodStatus[];
  duration_ms: number;
  created_at: string;
  findings: Finding[];
}

export interface Verification {
  dataset_id: string;
  status: "verified" | "modified";
  expected_sha256: string;
  actual_sha256: string;
  diff: {
    rows_added: number;
    rows_removed: number;
    changed_chunks: number[];
    columns_added: string[];
    columns_removed: string[];
    content_equivalent: boolean;
  };
}

export interface Provenance {
  record_id: string;
  dataset_id: string;
  manifest: Record<string, unknown>;
  signature: string;
  public_key_fingerprint: string;
  created_at: string;
  verification: { trusted: boolean; signature_valid: boolean; hash_matches: boolean; reasons: string[] };
}

export interface TrainingRun {
  id: string;
  name: string;
  status: string;
  parameters: Record<string, unknown>;
  notes: string;
  created_at: string;
  dataset_ids: string[];
}

export interface ModelArtifact {
  id: string;
  name: string;
  version: string;
  kind: "checkpoint" | "fine_tuned" | "lab";
  training_run_id: string | null;
  parent_model_id: string | null;
  sha256: string;
  status: "active" | "quarantined" | "retired";
  created_at: string;
}

export interface Deployment {
  id: string;
  model_id: string;
  environment: string;
  endpoint: string;
  status: string;
  created_at: string;
}

export interface TriggerResult {
  token: string;
  target: string;
  flip_rate: number;
  n: number;
  z_score: number;
}

export interface Evaluation {
  id: string;
  model_id: string;
  comparison_model_id: string | null;
  dataset_id: string;
  classification:
    | "confirmed_experimental_trigger"
    | "suspicious_behavior_detected"
    | "unverified_potential_backdoor"
    | "no_trigger_behavior_detected";
  results: {
    verdict: string;
    baseline: { accuracy: number; per_class_accuracy: Record<string, number>; n: number };
    control: { median_flip_rate: number; p95_flip_rate: number; tokens_tested: number };
    declared_triggers: TriggerResult[];
    suspicious_triggers: TriggerResult[];
    weak_signals: TriggerResult[];
    limitations: string[];
    comparison?: {
      prediction_agreement: number;
      accuracy_delta: number;
      behavior_regression: { passed: boolean; criteria: string };
      trigger_flip_rates: { token: string; target: string; model_flip_rate: number; comparison_flip_rate: number | null }[];
    };
  };
  duration_ms: number;
  created_at: string;
}

export interface IncidentEvent {
  id: string;
  kind: string;
  actor: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface ImpactItem {
  id: string;
  label: string;
  status: string | null;
  distance: number;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  state: IncidentState;
  created_at: string;
  updated_at: string;
  dataset_ids: string[];
  events: IncidentEvent[];
  impact: { datasets: ImpactItem[]; training_runs: ImpactItem[]; models: ImpactItem[]; deployments: ImpactItem[] } | null;
  recommendations: string[];
}

export interface GraphNode {
  id: string;
  kind: "dataset" | "training_run" | "model" | "deployment";
  ref: string;
  label: string;
  status?: string;
  risk_level?: RiskLevel;
  integrity_status?: string;
  quarantined?: boolean;
  highlighted: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
}

export interface LineageGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ActivityEvent {
  id: string;
  at: string;
  actor: string;
  action: string;
  target_type: string;
  target_id: string;
  summary: string;
}

export interface DashboardSummary {
  totals: Record<string, number>;
  integrity_status: Record<string, number>;
  risk_distribution: Record<string, number>;
  findings_by_severity: Record<string, number>;
  findings_by_method: Record<string, number>;
  evaluation_verdicts: Record<string, number>;
  incidents_by_state: Record<string, number>;
  detection_history: { date: string; inspections: number; findings: number }[];
  recent_activity: ActivityEvent[];
}

export interface SettingsInfo {
  environment: string;
  limits: { max_upload_bytes: number; max_rows: number; max_text_chars_per_cell: number };
  thresholds: Record<string, number>;
  detectors: string[];
  supported_formats: string[];
  signing_key: { algorithm: string; fingerprint: string; public_key_pem: string };
  rate_limit_per_minute: number;
}
