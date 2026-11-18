// Thin typed client for the TrustTrain API. The access token lives in memory
// and sessionStorage only (cleared when the tab closes); it is sent as a
// bearer header, never as a cookie.
import type {
  ActivityEvent,
  DashboardSummary,
  Dataset,
  Deployment,
  Evaluation,
  Finding,
  Incident,
  IncidentState,
  Inspection,
  LineageGraph,
  ModelArtifact,
  Provenance,
  Role,
  SettingsInfo,
  TrainingRun,
  User,
  Verification,
} from "../types";

const TOKEN_KEY = "trusttrain.token";
const BASE = import.meta.env.VITE_API_URL ?? "";

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let token: string | null = typeof sessionStorage !== "undefined" ? sessionStorage.getItem(TOKEN_KEY) : null;
let onUnauthorized: (() => void) | null = null;

export function setToken(value: string | null): void {
  token = value;
  if (value) sessionStorage.setItem(TOKEN_KEY, value);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export function getToken(): string | null {
  return token;
}

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  let resp: Response;
  try {
    resp = await fetch(`${BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "Cannot reach the TrustTrain API");
  }
  if (resp.status === 401 && onUnauthorized) onUnauthorized();
  if (!resp.ok) {
    let detail = resp.statusText || "Request failed";
    try {
      const body = await resp.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg?: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(resp.status, detail);
  }
  const type = resp.headers.get("content-type") ?? "";
  return (type.includes("application/json") ? resp.json() : resp.text()) as Promise<T>;
}

const json = (body: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(body) });
const query = (params: Record<string, string | undefined>): string => {
  const q = new URLSearchParams(Object.entries(params).filter((e): e is [string, string] => Boolean(e[1])));
  const s = q.toString();
  return s ? `?${s}` : "";
};

export const api = {
  login: (email: string, password: string) =>
    request<{ access_token: string; role: Role; expires_in: number }>("/api/auth/login", json({ email, password })),
  me: () => request<User>("/api/auth/me"),
  users: () => request<User[]>("/api/users"),
  createUser: (body: { email: string; password: string; role: Role }) => request<User>("/api/users", json(body)),

  summary: () => request<DashboardSummary>("/api/dashboard/summary"),
  activity: (limit = 100) => request<ActivityEvent[]>(`/api/activity?limit=${limit}`),
  settings: () => request<SettingsInfo>("/api/settings"),

  datasets: (filters: { risk_level?: string; integrity_status?: string } = {}) => request<Dataset[]>(`/api/datasets${query(filters)}`),
  dataset: (id: string) => request<Dataset>(`/api/datasets/${encodeURIComponent(id)}`),
  uploadDataset: (form: FormData) => request<Dataset>("/api/datasets", { method: "POST", body: form }),
  updateDataset: (id: string, body: { approval_status?: string; description?: string }) =>
    request<Dataset>(`/api/datasets/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(body) }),
  verifyDataset: (id: string) => request<Verification>(`/api/datasets/${encodeURIComponent(id)}/verify`, { method: "POST" }),
  provenance: (id: string) => request<Provenance>(`/api/datasets/${encodeURIComponent(id)}/provenance`),
  inspect: (id: string, body: Record<string, unknown> = {}) =>
    request<Inspection>(`/api/datasets/${encodeURIComponent(id)}/inspect`, json(body)),
  inspections: (id: string) => request<Inspection[]>(`/api/datasets/${encodeURIComponent(id)}/inspections`),

  findings: (filters: { severity?: string; method?: string; status?: string; dataset_id?: string } = {}) =>
    request<Finding[]>(`/api/findings${query(filters)}`),
  updateFinding: (id: string, status: Finding["status"]) =>
    request<Finding>(`/api/findings/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ status }) }),

  trainingRuns: () => request<TrainingRun[]>("/api/training-runs"),
  createTrainingRun: (body: { name: string; dataset_ids: string[]; notes?: string }) => request<TrainingRun>("/api/training-runs", json(body)),
  models: () => request<ModelArtifact[]>("/api/models"),
  registerModel: (body: { name: string; version?: string; kind?: string; training_run_id?: string | null; parent_model_id?: string | null }) =>
    request<ModelArtifact>("/api/models", json(body)),
  trainLabModel: (body: { name: string; dataset_id: string; epochs?: number }) => request<ModelArtifact>("/api/models/lab", json(body)),
  deployments: () => request<Deployment[]>("/api/deployments"),
  createDeployment: (body: { model_id: string; environment: string; endpoint?: string }) => request<Deployment>("/api/deployments", json(body)),

  evaluations: () => request<Evaluation[]>("/api/evaluations"),
  runEvaluation: (body: { model_id: string; dataset_id: string; comparison_model_id?: string | null; declared_triggers?: string[] }) =>
    request<Evaluation>("/api/evaluations", json(body)),

  lineage: () => request<LineageGraph>("/api/lineage/graph"),
  downstream: (datasetId: string) =>
    request<{ total_affected: number; graph: LineageGraph; affected: Record<string, { id: string; label: string }[]> }>(
      `/api/lineage/datasets/${encodeURIComponent(datasetId)}/downstream`,
    ),

  incidents: (state?: IncidentState) => request<Incident[]>(`/api/incidents${query({ state })}`),
  incident: (id: string) => request<Incident>(`/api/incidents/${encodeURIComponent(id)}`),
  createIncident: (body: { title: string; description?: string; severity?: string; dataset_ids?: string[] }) =>
    request<Incident>("/api/incidents", json(body)),
  transitionIncident: (id: string, state: IncidentState, comment = "") =>
    request<Incident>(`/api/incidents/${encodeURIComponent(id)}/transition`, json({ state, comment })),
  addIncidentNote: (id: string, note: string) => request<Incident>(`/api/incidents/${encodeURIComponent(id)}/notes`, json({ note })),
  quarantine: (id: string, body: { target_type: "dataset" | "model"; target_id: string; action: "quarantine" | "release"; reason: string }) =>
    request<Incident>(`/api/incidents/${encodeURIComponent(id)}/quarantine`, json(body)),
  addRemediation: (id: string, body: { action: string; description: string; completed: boolean }) =>
    request<Incident>(`/api/incidents/${encodeURIComponent(id)}/remediations`, json(body)),
  incidentReportMarkdown: (id: string) => request<string>(`/api/incidents/${encodeURIComponent(id)}/report?format=markdown`),
  datasetReport: (id: string) => request<Record<string, unknown>>(`/api/reports/datasets/${encodeURIComponent(id)}`),
};
