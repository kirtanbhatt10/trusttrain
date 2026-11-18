import { useState } from "react";
import { Link } from "react-router-dom";
import { FindingCard } from "../components/FindingCard";
import { Card, EmptyState, ErrorState, Loading, PageHeader, humanize, inputClass } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";

const METHODS = [
  "statistical_anomaly",
  "duplicate_detection",
  "label_inconsistency",
  "embedding_outlier",
  "suspicious_instruction_pattern",
  "trigger_token_association",
  "semantic_inconsistency",
  "distribution_shift",
];

export function SecurityFindings() {
  const { can } = useAuth();
  const [severity, setSeverity] = useState("");
  const [method, setMethod] = useState("");
  const [status, setStatus] = useState("open");
  const findings = useApi(() => api.findings({ severity, method, status }), [severity, method, status]);
  const datasets = useApi(() => api.datasets());
  const action = useAction();
  const names = new Map(datasets.data?.map((d) => [d.id, `${d.name} v${d.version}`]));

  return (
    <>
      <PageHeader
        title="Security Findings"
        description="Explainable detector output across all datasets. Each finding lists evidence, confidence, methodology and limitations."
      />
      <div className="mb-4 flex flex-wrap gap-2" role="group" aria-label="Filters">
        <select aria-label="Severity" className={`${inputClass} w-40`} value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>
              {humanize(s)}
            </option>
          ))}
        </select>
        <select aria-label="Detection method" className={`${inputClass} w-64`} value={method} onChange={(e) => setMethod(e.target.value)}>
          <option value="">All detection methods</option>
          {METHODS.map((m) => (
            <option key={m} value={m}>
              {humanize(m)}
            </option>
          ))}
        </select>
        <select aria-label="Status" className={`${inputClass} w-40`} value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Any status</option>
          {["open", "acknowledged", "dismissed"].map((s) => (
            <option key={s} value={s}>
              {humanize(s)}
            </option>
          ))}
        </select>
      </div>
      {action.error && <ErrorState message={action.error} />}
      {findings.loading && !findings.data ? (
        <Loading />
      ) : findings.error ? (
        <ErrorState message={findings.error} onRetry={findings.reload} />
      ) : findings.data?.length === 0 ? (
        <EmptyState title="No findings match these filters." />
      ) : (
        <Card title={`${findings.data?.length ?? 0} finding(s)`}>
          <div className="space-y-3">
            {findings.data?.map((f) => (
              <div key={f.id}>
                <Link to={`/inspection/${f.dataset_id}`} className="mb-1 inline-block text-xs text-ink-2 hover:text-accent">
                  {names.get(f.dataset_id) ?? f.dataset_id}
                </Link>
                <FindingCard
                  finding={f}
                  onStatus={can("analyst") ? (s) => action.run(() => api.updateFinding(f.id, s)).then(findings.reload) : undefined}
                />
              </div>
            ))}
          </div>
        </Card>
      )}
    </>
  );
}
