import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { FindingCard } from "../components/FindingCard";
import { Badge, Button, Card, EmptyState, ErrorState, Field, Loading, Mono, PageHeader, RiskBadge, formatDate, humanize, inputClass } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";
import type { Dataset } from "../types";

function DatasetDetail({ dataset, datasets, onChange }: { dataset: Dataset; datasets: Dataset[]; onChange: () => void }) {
  const { can } = useAuth();
  const inspections = useApi(() => api.inspections(dataset.id), [dataset.id]);
  const provenance = useApi(() => api.provenance(dataset.id), [dataset.id]);
  const action = useAction();
  const [reference, setReference] = useState("");
  const [labelColumn, setLabelColumn] = useState("");
  const [textColumn, setTextColumn] = useState("");
  const latest = inspections.data?.[0];

  const runInspection = async () => {
    const body: Record<string, unknown> = {};
    if (reference) body.reference_dataset_id = reference;
    if (labelColumn) body.label_column = labelColumn;
    if (textColumn) body.text_column = textColumn;
    if (await action.run(() => api.inspect(dataset.id, body))) {
      inspections.reload();
      onChange();
    }
  };
  const verify = async () => {
    if (await action.run(() => api.verifyDataset(dataset.id))) {
      provenance.reload();
      onChange();
    }
  };
  const approve = async (status: "approved" | "rejected") => {
    if (await action.run(() => api.updateDataset(dataset.id, { approval_status: status }))) {
      provenance.reload();
      onChange();
    }
  };
  const setFinding = async (id: string, status: "acknowledged" | "dismissed") => {
    if (await action.run(() => api.updateFinding(id, status))) inspections.reload();
  };

  return (
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Dataset" className="lg:col-span-2">
          <dl className="grid grid-cols-[9rem_1fr] gap-y-2 text-sm">
            <dt className="text-muted">Name</dt>
            <dd>
              {dataset.name} v{dataset.version}
            </dd>
            <dt className="text-muted">File</dt>
            <dd>
              {dataset.original_filename} ({dataset.file_format.toUpperCase()}, {dataset.row_count.toLocaleString()} rows)
            </dd>
            <dt className="text-muted">Columns</dt>
            <dd className="text-ink-2">{dataset.columns.join(", ")}</dd>
            <dt className="text-muted">SHA-256</dt>
            <dd>
              <Mono>{dataset.sha256}</Mono>
            </dd>
            <dt className="text-muted">Status</dt>
            <dd className="flex flex-wrap gap-2">
              <Badge value={dataset.integrity_status} />
              <RiskBadge risk={dataset.risk_level} />
              <Badge value={dataset.approval_status} />
              {dataset.quarantined && <Badge value="quarantined" />}
            </dd>
          </dl>
          {can("analyst") && (
            <div className="mt-4 flex flex-wrap gap-2">
              <Button variant="secondary" onClick={verify} disabled={action.pending}>
                Verify integrity
              </Button>
              {can("admin") && dataset.approval_status !== "approved" && (
                <Button variant="secondary" onClick={() => approve("approved")} disabled={action.pending || dataset.quarantined}>
                  Approve and sign
                </Button>
              )}
              {can("admin") && dataset.approval_status !== "rejected" && (
                <Button variant="danger" onClick={() => approve("rejected")} disabled={action.pending}>
                  Reject
                </Button>
              )}
            </div>
          )}
        </Card>
        <Card title="Provenance">
          {provenance.loading ? (
            <Loading />
          ) : provenance.error ? (
            <ErrorState message={provenance.error} />
          ) : provenance.data ? (
            <div className="space-y-2 text-sm">
              <Badge value={provenance.data.verification.trusted ? "verified" : "modified"} label={provenance.data.verification.trusted ? "Signed and trusted" : "Untrusted"} />
              <p className="text-ink-2">
                Ed25519 key <Mono>{provenance.data.public_key_fingerprint.slice(0, 16)}…</Mono>
              </p>
              <p className="text-xs text-muted">Signed {formatDate(provenance.data.created_at)}</p>
              {provenance.data.verification.reasons.map((r) => (
                <p key={r} className="text-xs text-critical">
                  {r}
                </p>
              ))}
            </div>
          ) : null}
        </Card>
      </div>

      {can("analyst") && (
        <Card title="Run inspection">
          <div className="grid gap-3 md:grid-cols-4">
            <Field label="Reference dataset" hint="Enables distribution comparison (defaults to parent).">
              <select className={inputClass} value={reference} onChange={(e) => setReference(e.target.value)}>
                <option value="">— parent / none —</option>
                {datasets
                  .filter((d) => d.id !== dataset.id)
                  .map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name} v{d.version}
                    </option>
                  ))}
              </select>
            </Field>
            <Field label="Text column" hint="Auto-detected if empty.">
              <select className={inputClass} value={textColumn} onChange={(e) => setTextColumn(e.target.value)}>
                <option value="">auto</option>
                {dataset.columns.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </Field>
            <Field label="Label column" hint="Auto-detected if empty.">
              <select className={inputClass} value={labelColumn} onChange={(e) => setLabelColumn(e.target.value)}>
                <option value="">auto</option>
                {dataset.columns.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </Field>
            <div className="flex items-end">
              <Button onClick={runInspection} disabled={action.pending}>
                {action.pending ? "Inspecting…" : "Run all detectors"}
              </Button>
            </div>
          </div>
          {action.error && (
            <p role="alert" className="mt-3 text-sm text-critical">
              {action.error}
            </p>
          )}
        </Card>
      )}

      <Card title="Latest inspection">
        {inspections.loading && !inspections.data ? (
          <Loading />
        ) : inspections.error ? (
          <ErrorState message={inspections.error} onRetry={inspections.reload} />
        ) : !latest ? (
          <EmptyState title="This dataset has not been inspected yet." />
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <RiskBadge risk={latest.risk_level} />
              <span className="text-ink-2">
                score {latest.risk_score.toFixed(2)} · {latest.findings.length} finding(s) · {latest.duration_ms} ms · {formatDate(latest.created_at)}
              </span>
            </div>
            <p className="text-xs text-muted">Risk summarises how much evidence warrants investigation. It is not proof of malicious poisoning.</p>
            <ul className="grid gap-1 text-xs md:grid-cols-2">
              {latest.methods.map((m) => (
                <li key={m.method} className="flex justify-between gap-2 rounded border border-line/60 px-2 py-1">
                  <span>{humanize(m.method)}</span>
                  <span className={m.status === "error" ? "text-critical" : "text-ink-2"}>
                    {m.status === "ran" ? `${m.findings} finding(s), ${m.duration_ms} ms` : `${m.status}: ${m.reason}`}
                  </span>
                </li>
              ))}
            </ul>
            <div className="space-y-2">
              {latest.findings.map((f) => (
                <FindingCard key={f.id} finding={f} onStatus={can("analyst") ? (s) => setFinding(f.id, s as "acknowledged" | "dismissed") : undefined} />
              ))}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

export function DatasetInspection() {
  const { datasetId } = useParams();
  const navigate = useNavigate();
  const { data, error, loading, reload } = useApi(() => api.datasets());
  const dataset = data?.find((d) => d.id === datasetId);

  return (
    <>
      <PageHeader
        title="Dataset Inspection"
        description="Fingerprint verification, signed provenance and poisoning detectors for a single dataset version."
        actions={
          data && data.length > 0 ? (
            <select aria-label="Select dataset" className={`${inputClass} w-72`} value={datasetId ?? ""} onChange={(e) => navigate(`/inspection/${e.target.value}`)}>
              <option value="" disabled>
                Select a dataset…
              </option>
              {data.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name} v{d.version}
                </option>
              ))}
            </select>
          ) : undefined
        }
      />
      {loading && !data ? (
        <Loading />
      ) : error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : !data?.length ? (
        <EmptyState title="No datasets registered yet.">Upload one from the Dataset Inventory.</EmptyState>
      ) : !dataset ? (
        <EmptyState title={datasetId ? "Dataset not found." : "Select a dataset to inspect."} />
      ) : (
        <DatasetDetail key={dataset.id} dataset={dataset} datasets={data} onChange={reload} />
      )}
    </>
  );
}
