import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  Badge,
  Button,
  Card,
  ErrorState,
  Field,
  Loading,
  Mono,
  PageHeader,
  RiskBadge,
  Table,
  formatBytes,
  formatDate,
  inputClass,
  shortHash,
} from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";
import type { Dataset } from "../types";

function UploadForm({ datasets, onDone }: { datasets: Dataset[]; onDone: () => void }) {
  const { pending, error, run } = useAction();
  const [file, setFile] = useState<File | null>(null);
  const [parent, setParent] = useState("");

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!file) return;
    const form = new FormData(e.currentTarget);
    if (!parent) {
      form.delete("parent_id");
      form.delete("operation");
    }
    const result = await run(() => api.uploadDataset(form));
    if (result) {
      e.currentTarget?.reset();
      setFile(null);
      setParent("");
      onDone();
    }
  };

  return (
    <form onSubmit={submit} className="grid gap-3 md:grid-cols-3" aria-label="Upload dataset">
      <Field label="Dataset file" hint="CSV, JSON, JSONL, Parquet or TXT. Archives and pickles are rejected.">
        <input
          name="file"
          type="file"
          required
          accept=".csv,.json,.jsonl,.ndjson,.parquet,.txt"
          className="block w-full text-sm text-ink-2 file:mr-3 file:rounded-md file:border-0 file:bg-raised file:px-3 file:py-1.5 file:text-ink"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
      </Field>
      <Field label="Name">
        <input name="name" className={inputClass} placeholder="defaults to file name" maxLength={200} />
      </Field>
      <Field label="Version">
        <input name="version" className={inputClass} defaultValue="1" maxLength={64} />
      </Field>
      <Field label="Source">
        <input name="source" className={inputClass} placeholder="e.g. vendor export, s3://bucket/path" maxLength={500} />
      </Field>
      <Field label="Derived from (optional)">
        <select name="parent_id" className={inputClass} value={parent} onChange={(e) => setParent(e.target.value)}>
          <option value="">— none —</option>
          {datasets.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name} v{d.version}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Processing operation">
        <input name="operation" className={inputClass} placeholder="e.g. dedupe, filter, tokenize" disabled={!parent} maxLength={120} />
      </Field>
      <div className="flex items-center gap-3 md:col-span-3">
        <Button type="submit" disabled={!file || pending}>
          {pending ? "Uploading and fingerprinting…" : "Upload and fingerprint"}
        </Button>
        {error && (
          <span role="alert" className="text-sm text-critical">
            {error}
          </span>
        )}
      </div>
    </form>
  );
}

export function DatasetInventory() {
  const { can } = useAuth();
  const [risk, setRisk] = useState("");
  const [integrity, setIntegrity] = useState("");
  const { data, error, loading, reload } = useApi(() => api.datasets({ risk_level: risk, integrity_status: integrity }), [risk, integrity]);
  const verify = useAction();

  return (
    <>
      <PageHeader title="Dataset Inventory" description="Every registered dataset version with its fingerprint, provenance and integrity state." />
      {can("analyst") && (
        <Card title="Register a dataset" className="mb-6">
          <UploadForm datasets={data ?? []} onDone={reload} />
        </Card>
      )}
      <Card
        title="Datasets"
        actions={
          <div className="flex gap-2">
            <select aria-label="Filter by risk" className={`${inputClass} w-36`} value={risk} onChange={(e) => setRisk(e.target.value)}>
              <option value="">All risk levels</option>
              {["critical", "high", "medium", "low", "none", "unknown"].map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <select aria-label="Filter by integrity" className={`${inputClass} w-36`} value={integrity} onChange={(e) => setIntegrity(e.target.value)}>
              <option value="">All integrity</option>
              {["verified", "modified", "unverified"].map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {verify.error && <ErrorState message={verify.error} />}
        {loading && !data ? (
          <Loading />
        ) : error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : (
          <Table head={["Dataset", "Format", "Rows", "Size", "SHA-256", "Integrity", "Risk", "Approval", "Imported", ""]} empty={data?.length === 0}>
            {data?.map((d) => (
              <tr key={d.id} className="align-middle">
                <td className="px-3 py-2">
                  <Link to={`/inspection/${d.id}`} className="font-medium text-ink hover:text-accent">
                    {d.name}
                  </Link>
                  <div className="text-xs text-muted">
                    v{d.version}
                    {d.source && ` · ${d.source}`}
                    {d.quarantined && " · "}
                    {d.quarantined && <Badge value="quarantined" />}
                  </div>
                </td>
                <td className="px-3 py-2 uppercase text-ink-2">{d.file_format}</td>
                <td className="px-3 py-2 tabular-nums">{d.row_count.toLocaleString()}</td>
                <td className="px-3 py-2 tabular-nums text-ink-2">{formatBytes(d.size_bytes)}</td>
                <td className="px-3 py-2">
                  <Mono title={d.sha256}>{shortHash(d.sha256)}</Mono>
                </td>
                <td className="px-3 py-2">
                  <Badge value={d.integrity_status} />
                </td>
                <td className="px-3 py-2">
                  <RiskBadge risk={d.risk_level} />
                </td>
                <td className="px-3 py-2">
                  <Badge value={d.approval_status} />
                </td>
                <td className="px-3 py-2 text-xs text-ink-2">{formatDate(d.created_at)}</td>
                <td className="px-3 py-2 text-right">
                  {can("analyst") && (
                    <Button variant="secondary" disabled={verify.pending} onClick={() => verify.run(() => api.verifyDataset(d.id)).then(reload)}>
                      Verify
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
