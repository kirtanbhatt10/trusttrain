import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { App } from "../App";
import { NAV } from "../components/Layout";
import { AuthProvider } from "../hooks/useAuth";
import { setToken } from "../services/api";
import { dataset, finding, incident, mockFetch, summary, user } from "./mockApi";

const emptyRoutes = {
  "GET /api/auth/me": user,
  "GET /api/dashboard/summary": { ...summary, totals: { ...summary.totals, datasets: 0 } },
  "GET /api/datasets": [],
  "GET /api/findings": [],
  "GET /api/models": [],
  "GET /api/evaluations": [],
  "GET /api/lineage/graph": { nodes: [], edges: [] },
  "GET /api/training-runs": [],
  "GET /api/deployments": [],
  "GET /api/incidents": [],
  "GET /api/users": [user],
  "GET /api/activity": [],
  "GET /api/settings": {
    environment: "development",
    limits: { max_upload_bytes: 52428800, max_rows: 200000, max_text_chars_per_cell: 20000 },
    thresholds: { zscore_threshold: 4 },
    detectors: ["statistical_anomaly"],
    supported_formats: ["csv"],
    signing_key: { algorithm: "Ed25519", fingerprint: "f".repeat(64), public_key_pem: "-----BEGIN PUBLIC KEY-----" },
    rate_limit_per_minute: 240,
  },
};

function renderApp(path = "/", authenticated = true) {
  if (authenticated) setToken("token");
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("authentication", () => {
  it("shows the login form and signs in", async () => {
    const { calls } = mockFetch({ ...emptyRoutes, "POST /api/auth/login": { access_token: "t1", role: "admin", expires_in: 3600 } });
    renderApp("/", false);
    await userEvent.type(await screen.findByLabelText("Email"), "analyst@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(calls.find((c) => c.path === "/api/auth/login")).toBeDefined();
  });

  it("shows login errors", async () => {
    mockFetch({ "POST /api/auth/login": new Response(JSON.stringify({ detail: "Invalid email or password" }), { status: 401 }) });
    renderApp("/", false);
    await userEvent.type(await screen.findByLabelText("Email"), "a@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password");
  });

  it("returns to login when the stored token is rejected", async () => {
    mockFetch({ "GET /api/auth/me": new Response(JSON.stringify({ detail: "Not authenticated" }), { status: 401 }) });
    renderApp("/");
    expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });
});

describe("navigation", () => {
  it("renders every page from the sidebar", async () => {
    mockFetch(emptyRoutes);
    renderApp("/");
    await screen.findByRole("heading", { name: "Overview" });
    const nav = screen.getByRole("navigation", { name: "Main" });
    for (const item of NAV) {
      await userEvent.click(within(nav).getByRole("link", { name: item.label }));
      expect(await screen.findByRole("heading", { level: 1, name: item.label })).toBeInTheDocument();
    }
  });
});

describe("overview dashboard", () => {
  it("renders metrics from the API", async () => {
    mockFetch({ ...emptyRoutes, "GET /api/dashboard/summary": summary });
    renderApp("/");
    expect(await screen.findByText("Inspection found 5 findings; risk critical")).toBeInTheDocument();
    expect(screen.getByText("1 failed integrity checks")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Datasets by risk level" })).toHaveTextContent("Critical");
    expect(screen.getByRole("img", { name: "Inspections and findings per day" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show table" }));
    expect(screen.getByRole("cell", { name: "2026-11-02" })).toBeInTheDocument();
  });

  it("shows an empty state with no datasets", async () => {
    mockFetch(emptyRoutes);
    renderApp("/");
    expect(await screen.findByText("No datasets registered yet")).toBeInTheDocument();
  });

  it("shows an error state and retries", async () => {
    let fail = true;
    mockFetch({
      ...emptyRoutes,
      "GET /api/dashboard/summary": () => (fail ? new Response(JSON.stringify({ detail: "database unavailable" }), { status: 500 }) : summary),
    });
    renderApp("/");
    expect(await screen.findByRole("alert")).toHaveTextContent("database unavailable");
    fail = false;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Inspection found 5 findings; risk critical")).toBeInTheDocument();
  });

  it("shows a loading state while fetching", async () => {
    mockFetch({ ...emptyRoutes, "GET /api/dashboard/summary": () => new Promise(() => {}) });
    renderApp("/");
    expect(await screen.findByText("Loading…")).toBeInTheDocument();
  });
});

describe("dataset inspection", () => {
  it("runs an inspection and shows explainable findings", async () => {
    const inspection = {
      id: "i-1", dataset_id: "ds-1", reference_dataset_id: null, status: "completed", risk_level: "critical", risk_score: 0.9, config: {},
      methods: [{ method: "distribution_shift", status: "skipped", reason: "no reference dataset supplied", duration_ms: 0, findings: 0 }],
      duration_ms: 812, created_at: "2026-11-01T10:05:00Z", findings: [finding],
    };
    let inspected = false;
    const { calls } = mockFetch({
      ...emptyRoutes,
      "GET /api/datasets": [dataset],
      "GET /api/datasets/ds-1/inspections": () => (inspected ? [inspection] : []),
      "GET /api/datasets/ds-1/provenance": {
        record_id: "p1", dataset_id: "ds-1", manifest: {}, signature: "s", public_key_fingerprint: "b".repeat(64), created_at: "2026-11-01T10:00:00Z",
        verification: { trusted: true, signature_valid: true, hash_matches: true, reasons: [] },
      },
      "POST /api/datasets/ds-1/inspect": () => {
        inspected = true;
        return inspection;
      },
    });
    renderApp("/inspection/ds-1");
    expect(await screen.findByText("This dataset has not been inspected yet.")).toBeInTheDocument();
    expect(screen.getByText("Signed and trusted")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Run all detectors" }));
    expect(await screen.findByText(finding.title)).toBeInTheDocument();
    expect(screen.getByText(/skipped: no reference dataset supplied/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Evidence" }));
    expect(screen.getByText(/Multi-token triggers are not detected/)).toBeInTheDocument();
    expect(screen.getByText(/and 37 more/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST" && c.path === "/api/datasets/ds-1/inspect")).toBe(true);
  });
});

describe("security findings", () => {
  it("filters findings and updates status", async () => {
    const { calls } = mockFetch({
      ...emptyRoutes,
      "GET /api/datasets": [dataset],
      "GET /api/findings": [finding],
      "PATCH /api/findings/f-1": { ...finding, status: "acknowledged" },
    });
    renderApp("/findings");
    expect(await screen.findByText(finding.title)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Severity"), "high");
    await waitFor(() => expect(calls.some((c) => c.path === "/api/findings" && String(c.init.method ?? "GET") === "GET")).toBe(true));
    const lastFindingsCall = (globalThis.fetch as unknown as { mock: { calls: [string][] } }).mock.calls.map((c) => String(c[0])).filter((u) => u.startsWith("/api/findings?")).pop();
    expect(lastFindingsCall).toContain("severity=high");
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH" && c.path === "/api/findings/f-1")).toBe(true));
  });
});

describe("incident management", () => {
  it("shows impact, transitions state and records notes", async () => {
    const { calls } = mockFetch({
      ...emptyRoutes,
      "GET /api/incidents": [incident],
      "GET /api/incidents/inc-1": incident,
      "POST /api/incidents/inc-1/transition": { ...incident, state: "remediation_required" },
      "POST /api/incidents/inc-1/notes": incident,
    });
    renderApp("/incidents/inc-1");
    expect(await screen.findByRole("option", { name: "Model sentiment v1 (active)" })).toBeInTheDocument();
    expect(screen.getByText("sentiment v1")).toBeInTheDocument(); // impact list
    expect(screen.getByText(incident.recommendations[0])).toBeInTheDocument();
    // Only transitions allowed from "under_investigation" are offered.
    expect(screen.getByRole("button", { name: "Quarantined" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remediation required" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/api/incidents/inc-1/transition")).toBe(true));
    await userEvent.type(screen.getByLabelText("Note"), "Found 40 rows with cf");
    await userEvent.click(screen.getByRole("button", { name: "Add note" }));
    await waitFor(() => {
      const call = calls.find((c) => c.path === "/api/incidents/inc-1/notes");
      expect(call && JSON.parse(String(call.init.body))).toEqual({ note: "Found 40 rows with cf" });
    });
  });

  it("creates an incident", async () => {
    const { calls } = mockFetch({
      ...emptyRoutes,
      "GET /api/datasets": [dataset],
      "POST /api/incidents": { ...incident, id: "inc-2" },
      "GET /api/incidents/inc-2": { ...incident, id: "inc-2" },
    });
    renderApp("/incidents");
    await userEvent.click(await screen.findByRole("button", { name: "New incident" }));
    const form = screen.getByRole("form", { name: "Create incident" });
    await userEvent.type(within(form).getByLabelText("Title"), "Suspicious upload");
    await userEvent.click(within(form).getByRole("button", { name: "Open incident" }));
    await waitFor(() => {
      const call = calls.find((c) => c.method === "POST" && c.path === "/api/incidents");
      expect(call && JSON.parse(String(call.init.body)).title).toBe("Suspicious upload");
    });
  });
});

describe("supply chain graph", () => {
  it("renders nodes and highlights downstream artifacts", async () => {
    mockFetch({
      ...emptyRoutes,
      "GET /api/lineage/graph": {
        nodes: [
          { id: "dataset:ds-1", kind: "dataset", ref: "ds-1", label: "reviews v1", highlighted: false },
          { id: "training_run:r1", kind: "training_run", ref: "r1", label: "run-1", highlighted: false },
          { id: "model:m1", kind: "model", ref: "m1", label: "sentiment v1", status: "quarantined", highlighted: false },
        ],
        edges: [
          { source: "dataset:ds-1", target: "training_run:r1", relation: "trained" },
          { source: "training_run:r1", target: "model:m1", relation: "produced" },
        ],
      },
      "GET /api/lineage/datasets/ds-1/downstream": {
        total_affected: 2, graph: { nodes: [], edges: [] },
        affected: { datasets: [], training_runs: [{ id: "r1", label: "run-1" }], models: [{ id: "m1", label: "sentiment v1" }], deployments: [] },
      },
    });
    renderApp("/supply-chain");
    await userEvent.click(await screen.findByRole("button", { name: "Dataset: reviews v1" }));
    expect(screen.getByText("2 downstream artifact(s) highlighted")).toBeInTheDocument();
    expect(await screen.findByText(/recorded downstream artifact\(s\) depend on/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Model: sentiment v1 (flagged)" })).toBeInTheDocument();
  });
});
