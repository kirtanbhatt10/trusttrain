import { vi } from "vitest";

export type Handler = (url: URL, init: RequestInit) => unknown | Promise<unknown>;

/** Install a fetch mock routing "METHOD /path" keys to handlers. Unmatched routes return 404. */
export function mockFetch(routes: Record<string, Handler | unknown>) {
  const calls: { method: string; path: string; init: RequestInit }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://localhost");
    const method = (init.method ?? "GET").toUpperCase();
    calls.push({ method, path: url.pathname, init });
    const key = `${method} ${url.pathname}`;
    const route = routes[key] ?? routes[`${method} ${url.pathname}${url.search}`];
    if (route === undefined) return new Response(JSON.stringify({ detail: `No mock for ${key}` }), { status: 404, headers: { "content-type": "application/json" } });
    const value = typeof route === "function" ? await (route as Handler)(url, init) : route;
    if (value instanceof Response) return value;
    if (typeof value === "string") return new Response(value, { status: 200, headers: { "content-type": "text/markdown" } });
    return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}

export const user = { id: "u1", email: "analyst@example.com", role: "admin", is_active: true, created_at: "2026-11-01T10:00:00Z" };

export const dataset = {
  id: "ds-1",
  name: "reviews",
  version: "1",
  source: "synthetic",
  description: "",
  file_format: "csv",
  original_filename: "reviews.csv",
  size_bytes: 2048,
  sha256: "a".repeat(64),
  row_count: 1282,
  columns: ["id", "text", "label", "rating"],
  parent_id: null,
  approval_status: "pending",
  integrity_status: "verified",
  risk_level: "critical",
  quarantined: false,
  created_at: "2026-11-01T10:00:00Z",
};

export const finding = {
  id: "f-1",
  inspection_id: "i-1",
  dataset_id: "ds-1",
  severity: "high",
  method: "trigger_token_association",
  title: "Token 'cf' behaves like a backdoor trigger for label 'positive'",
  confidence: 0.9,
  explanation: "The token, not the content, carries the label.",
  evidence: { token: "cf", row_indices: [1, 2, 3], row_indices_total: 40 },
  investigation_steps: ["Search the raw sources for 'cf'."],
  limitations: "Multi-token triggers are not detected.",
  status: "open",
  created_at: "2026-11-01T10:05:00Z",
};

export const summary = {
  totals: { datasets: 3, inspections: 2, open_findings: 5, training_runs: 1, models: 2, deployments: 1, evaluations: 1, quarantined_datasets: 0, quarantined_models: 1 },
  integrity_status: { verified: 2, modified: 1 },
  risk_distribution: { critical: 1, low: 2 },
  findings_by_severity: { high: 3, low: 2 },
  findings_by_method: { trigger_token_association: 1 },
  evaluation_verdicts: { confirmed_experimental_trigger: 1 },
  incidents_by_state: { under_investigation: 1, resolved: 2 },
  detection_history: [
    { date: "2026-11-01", inspections: 1, findings: 3, by_risk: {} },
    { date: "2026-11-02", inspections: 1, findings: 2, by_risk: {} },
  ],
  recent_activity: [
    { id: "a1", at: "2026-11-02T09:00:00Z", actor: "analyst@example.com", action: "dataset.inspected", target_type: "dataset", target_id: "ds-1", summary: "Inspection found 5 findings; risk critical" },
  ],
};

export const incident = {
  id: "inc-1",
  title: "Trigger token in reviews",
  description: "Investigating cf",
  severity: "high",
  state: "under_investigation",
  created_at: "2026-11-02T09:00:00Z",
  updated_at: "2026-11-02T09:30:00Z",
  dataset_ids: ["ds-1"],
  events: [{ id: "e1", kind: "created", actor: "analyst@example.com", detail: { severity: "high", dataset_ids: ["ds-1"] }, created_at: "2026-11-02T09:00:00Z" }],
  impact: {
    datasets: [],
    training_runs: [{ id: "run-1", label: "run-1", status: "recorded", distance: 1 }],
    models: [{ id: "m-1", label: "sentiment v1", status: "active", distance: 2 }],
    deployments: [],
  },
  recommendations: ["Consider quarantining dataset 'reviews v1' until the investigation concludes."],
};
