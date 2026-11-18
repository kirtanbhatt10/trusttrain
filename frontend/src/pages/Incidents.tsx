import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Badge, Button, Card, EmptyState, ErrorState, Field, Loading, PageHeader, SeverityBadge, formatDate, humanize, inputClass } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";
import type { Incident, IncidentState } from "../types";

// Mirrors backend/app/services/incidents.py TRANSITIONS.
export const TRANSITIONS: Record<IncidentState, IncidentState[]> = {
  open: ["under_investigation", "resolved"],
  under_investigation: ["quarantined", "remediation_required", "resolved"],
  quarantined: ["under_investigation", "remediation_required", "resolved"],
  remediation_required: ["under_investigation", "quarantined", "resolved"],
  resolved: ["under_investigation"],
};

function describeEvent(kind: string, d: Record<string, unknown>): string {
  switch (kind) {
    case "created":
      return `Incident opened (severity ${String(d.severity)})`;
    case "state_change":
      return `${humanize(String(d.from))} → ${humanize(String(d.to))}${d.comment ? `: ${String(d.comment)}` : ""}`;
    case "note":
      return String(d.note);
    case "quarantine":
    case "release":
      return `${kind === "quarantine" ? "Quarantined" : "Released"} ${String(d.target_type)} ${String(d.label)} — ${String(d.reason)}`;
    case "remediation":
      return `Remediation (${humanize(String(d.action))}${d.completed ? ", completed" : ""}): ${String(d.description)}`;
    case "dataset_associated":
      return `Associated dataset ${String(d.name)}`;
    default:
      return JSON.stringify(d);
  }
}

function IncidentDetail({ incident, onChange }: { incident: Incident; onChange: () => void }) {
  const { can } = useAuth();
  const action = useAction();
  const [comment, setComment] = useState("");
  const [note, setNote] = useState("");
  const impact = incident.impact;

  const act = async (fn: () => Promise<unknown>) => {
    if (await action.run(fn)) onChange();
  };
  const quarantine = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const [target_type, target_id] = String(f.get("target")).split(":") as ["dataset" | "model", string];
    void act(() => api.quarantine(incident.id, { target_type, target_id, action: f.get("action") as "quarantine" | "release", reason: String(f.get("reason")) }));
  };
  const remediation = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    void act(() => api.addRemediation(incident.id, { action: String(f.get("action")), description: String(f.get("description")), completed: f.get("completed") === "on" }));
  };

  const quarantineTargets = [
    ...incident.dataset_ids.map((id) => ({ value: `dataset:${id}`, label: `Dataset ${impact?.datasets.find((d) => d.id === id)?.label ?? id.slice(0, 8)}` })),
    ...(impact?.datasets ?? []).map((d) => ({ value: `dataset:${d.id}`, label: `Dataset ${d.label}` })),
    ...(impact?.models ?? []).map((m) => ({ value: `model:${m.id}`, label: `Model ${m.label} (${m.status ?? "active"})` })),
  ];

  return (
    <div className="space-y-4">
      <Card title={incident.title} actions={<Badge value={incident.state} />}>
        <div className="space-y-3 text-sm">
          <div className="flex flex-wrap items-center gap-2 text-ink-2">
            <SeverityBadge severity={incident.severity} /> opened {formatDate(incident.created_at)} · updated {formatDate(incident.updated_at)}
          </div>
          {incident.description && <p className="text-ink-2">{incident.description}</p>}
          {action.error && (
            <p role="alert" className="text-critical">
              {action.error}
            </p>
          )}
          {can("analyst") && (
            <div className="flex flex-wrap items-end gap-2">
              <input aria-label="Transition comment" className={`${inputClass} max-w-xs`} placeholder="Comment (required to resolve)" value={comment} onChange={(e) => setComment(e.target.value)} />
              {TRANSITIONS[incident.state].map((s) => (
                <Button key={s} variant="secondary" disabled={action.pending} onClick={() => act(() => api.transitionIncident(incident.id, s, comment)).then(() => setComment(""))}>
                  {humanize(s)}
                </Button>
              ))}
            </div>
          )}
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Affected artifacts (recorded lineage)">
          {impact ? (
            <dl className="space-y-2 text-sm">
              {(["datasets", "training_runs", "models", "deployments"] as const).map((k) => (
                <div key={k}>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-muted">
                    {humanize(k)} ({impact[k].length})
                  </dt>
                  <dd className="text-ink-2">{impact[k].length ? impact[k].map((i) => `${i.label}${i.status === "quarantined" ? " [quarantined]" : ""}`).join(", ") : "none"}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="text-sm text-ink-2">No datasets associated.</p>
          )}
        </Card>
        <Card title="Recommendations">
          <ul className="list-disc space-y-1 pl-5 text-sm text-ink-2">
            {incident.recommendations.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        </Card>
      </div>

      {can("analyst") && (
        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="Investigation note">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void act(() => api.addIncidentNote(incident.id, note)).then(() => setNote(""));
              }}
              className="space-y-2"
            >
              <textarea aria-label="Note" required className={`${inputClass} h-24`} value={note} onChange={(e) => setNote(e.target.value)} maxLength={10000} />
              <Button type="submit" disabled={action.pending}>
                Add note
              </Button>
            </form>
          </Card>
          <Card title="Remediation">
            <form onSubmit={remediation} className="space-y-2">
              <select name="action" aria-label="Remediation action" className={inputClass}>
                {["retrain", "rollback", "relabel", "remove_rows", "replace_source", "other"].map((a) => (
                  <option key={a} value={a}>
                    {humanize(a)}
                  </option>
                ))}
              </select>
              <input name="description" aria-label="Remediation description" required minLength={3} className={inputClass} placeholder="What was / will be done" />
              <label className="flex items-center gap-2 text-sm text-ink-2">
                <input type="checkbox" name="completed" /> Completed
              </label>
              <Button type="submit" disabled={action.pending}>
                Record remediation
              </Button>
            </form>
          </Card>
          <Card title="Quarantine (admin)">
            {can("admin") ? (
              <form onSubmit={quarantine} className="space-y-2">
                <select name="target" aria-label="Quarantine target" required className={inputClass}>
                  {quarantineTargets
                    .filter((t, i, all) => all.findIndex((o) => o.value === t.value) === i)
                    .map((t) => (
                      <option key={t.value} value={t.value}>
                        {t.label}
                      </option>
                    ))}
                </select>
                <select name="action" aria-label="Quarantine action" className={inputClass}>
                  <option value="quarantine">Quarantine</option>
                  <option value="release">Release</option>
                </select>
                <input name="reason" aria-label="Reason" required minLength={3} className={inputClass} placeholder="Reason (recorded in history)" />
                <Button type="submit" variant="danger" disabled={action.pending}>
                  Apply
                </Button>
                <p className="text-xs text-muted">Quarantine blocks training and deployment. Nothing is deleted.</p>
              </form>
            ) : (
              <p className="text-sm text-ink-2">Only administrators can quarantine or release artifacts.</p>
            )}
          </Card>
        </div>
      )}

      <Card title="Timeline" actions={<Link className="text-xs text-ink-2 underline underline-offset-2" to={`/reports?incident=${incident.id}`}>Generate report</Link>}>
        <ol className="space-y-2 text-sm">
          {incident.events.map((e) => (
            <li key={e.id} className="grid grid-cols-[10rem_1fr] gap-3">
              <span className="text-xs text-muted">{formatDate(e.created_at)}</span>
              <span>
                <span className="text-ink">{describeEvent(e.kind, e.detail)}</span>
                <span className="ml-2 text-xs text-muted">{e.actor}</span>
              </span>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}

function CreateIncident({ onCreated }: { onCreated: (id: string) => void }) {
  const datasets = useApi(() => api.datasets());
  const action = useAction();
  const [selected, setSelected] = useState<string[]>([]);
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const inc = await action.run(() =>
      api.createIncident({ title: String(f.get("title")), description: String(f.get("description") ?? ""), severity: String(f.get("severity")), dataset_ids: selected }),
    );
    if (inc) onCreated(inc.id);
  };
  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Create incident">
      <Field label="Title">
        <input name="title" required minLength={3} maxLength={300} className={inputClass} />
      </Field>
      <Field label="Severity">
        <select name="severity" defaultValue="medium" className={inputClass}>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>
              {humanize(s)}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Suspicious datasets">
        <select multiple className={`${inputClass} h-24`} value={selected} onChange={(e) => setSelected(Array.from(e.target.selectedOptions, (o) => o.value))}>
          {datasets.data?.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name} v{d.version}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Description">
        <textarea name="description" className={`${inputClass} h-20`} maxLength={10000} />
      </Field>
      {action.error && (
        <p role="alert" className="text-sm text-critical">
          {action.error}
        </p>
      )}
      <Button type="submit" disabled={action.pending}>
        Open incident
      </Button>
    </form>
  );
}

export function Incidents() {
  const { incidentId } = useParams();
  const navigate = useNavigate();
  const { can } = useAuth();
  const list = useApi(() => api.incidents());
  const detail = useApi(() => (incidentId ? api.incident(incidentId) : Promise.resolve(null)), [incidentId]);
  const [creating, setCreating] = useState(false);
  const refresh = () => {
    list.reload();
    detail.reload();
  };

  return (
    <>
      <PageHeader
        title="Security Incidents"
        description="Model recall and incident response: associate suspicious datasets, trace affected models, quarantine explicitly and track remediation."
        actions={can("analyst") ? <Button onClick={() => setCreating((v) => !v)}>{creating ? "Cancel" : "New incident"}</Button> : undefined}
      />
      {creating && (
        <Card title="Open an incident" className="mb-6">
          <CreateIncident
            onCreated={(id) => {
              setCreating(false);
              list.reload();
              navigate(`/incidents/${id}`);
            }}
          />
        </Card>
      )}
      <div className="grid gap-6 lg:grid-cols-[20rem_1fr]">
        <Card title="Incidents">
          {list.loading && !list.data ? (
            <Loading />
          ) : list.error ? (
            <ErrorState message={list.error} onRetry={list.reload} />
          ) : !list.data?.length ? (
            <EmptyState title="No incidents recorded." />
          ) : (
            <ul className="-m-2 space-y-1">
              {list.data.map((i) => (
                <li key={i.id}>
                  <Link to={`/incidents/${i.id}`} className={`block rounded-md p-2 ${i.id === incidentId ? "bg-raised" : "hover:bg-raised/60"}`}>
                    <div className="text-sm font-medium text-ink">{i.title}</div>
                    <div className="mt-1 flex flex-wrap gap-2">
                      <Badge value={i.state} />
                      <SeverityBadge severity={i.severity} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <div>
          {!incidentId ? (
            <EmptyState title="Select an incident to investigate." />
          ) : detail.loading && !detail.data ? (
            <Loading />
          ) : detail.error ? (
            <ErrorState message={detail.error} onRetry={detail.reload} />
          ) : detail.data ? (
            <IncidentDetail incident={detail.data} onChange={refresh} />
          ) : null}
        </div>
      </div>
    </>
  );
}
