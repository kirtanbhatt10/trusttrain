import { Link } from "react-router-dom";
import { BarList, HistoryChart, RISK_COLORS } from "../components/charts";
import { Card, EmptyState, ErrorState, Loading, PageHeader, Stat, formatDate, humanize } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

const RISK_ORDER = ["critical", "high", "medium", "low", "none", "unknown"];
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const INCIDENT_ORDER = ["open", "under_investigation", "quarantined", "remediation_required", "resolved"];
const INTEGRITY_COLORS: Record<string, string> = { verified: "#0ca30c", modified: "#d03b3b", unverified: "#898781" };
const VERDICT_COLORS: Record<string, string> = {
  confirmed_experimental_trigger: "#d03b3b",
  suspicious_behavior_detected: "#ec835a",
  unverified_potential_backdoor: "#fab219",
  no_trigger_behavior_detected: "#0ca30c",
};

const ordered = (counts: Record<string, number>, order: string[], colors: Record<string, string>) =>
  order.map((key) => ({ key, value: counts[key] ?? 0, color: colors[key] ?? "#898781" }));

export function Overview() {
  const { data, error, loading, reload } = useApi(api.summary);
  if (loading && !data) return <Loading />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return null;
  const t = data.totals;

  return (
    <>
      <PageHeader title="Overview" description="Integrity, risk and incident posture of your recorded ML supply chain. Every figure is computed from stored records." />
      {t.datasets === 0 ? (
        <EmptyState title="No datasets registered yet">
          <Link className="text-accent underline underline-offset-2" to="/datasets">
            Upload a dataset
          </Link>{" "}
          to start fingerprinting and inspection.
        </EmptyState>
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Datasets" value={t.datasets} hint={`${data.integrity_status.modified ?? 0} failed integrity checks`} />
            <Stat label="Open findings" value={t.open_findings} hint={`${t.inspections} inspections run`} />
            <Stat label="Models" value={t.models} hint={`${t.deployments} deployments · ${t.quarantined_models} quarantined`} />
            <Stat
              label="Active incidents"
              value={Object.entries(data.incidents_by_state).filter(([s]) => s !== "resolved").reduce((s, [, n]) => s + n, 0)}
              hint={`${data.incidents_by_state.resolved ?? 0} resolved`}
            />
          </div>
          <div className="grid gap-6 lg:grid-cols-2">
            <Card title="Dataset risk distribution">
              <BarList ariaLabel="Datasets by risk level" items={ordered(data.risk_distribution, RISK_ORDER, RISK_COLORS)} />
            </Card>
            <Card title="Dataset integrity">
              <BarList ariaLabel="Datasets by integrity status" items={ordered(data.integrity_status, ["verified", "modified", "unverified"], INTEGRITY_COLORS)} />
            </Card>
            <Card title="Detection history">
              <HistoryChart points={data.detection_history} />
            </Card>
            <Card title="Findings by severity">
              <BarList ariaLabel="Findings by severity" emptyText="No findings recorded." items={ordered(data.findings_by_severity, SEVERITY_ORDER, RISK_COLORS)} />
            </Card>
            <Card title="Model evaluation results">
              <BarList
                ariaLabel="Evaluations by verdict"
                emptyText="No backdoor evaluations yet."
                items={ordered(data.evaluation_verdicts, Object.keys(VERDICT_COLORS), VERDICT_COLORS)}
              />
            </Card>
            <Card title="Incidents by state">
              <BarList
                ariaLabel="Incidents by state"
                emptyText="No incidents recorded."
                items={INCIDENT_ORDER.map((key) => ({ key, value: data.incidents_by_state[key] ?? 0, color: "#3987e5" }))}
              />
            </Card>
          </div>
          <Card title="Recent activity" actions={<Link to="/settings" className="text-xs text-ink-2 underline underline-offset-2">Audit log</Link>}>
            <ul className="divide-y divide-line/60 text-sm">
              {data.recent_activity.map((e) => (
                <li key={e.id} className="flex flex-wrap items-baseline justify-between gap-2 py-2">
                  <span>
                    <span className="text-ink">{e.summary}</span>
                    <span className="ml-2 text-xs text-muted">{humanize(e.action.replace(".", " "))}</span>
                  </span>
                  <span className="text-xs text-ink-2">
                    {e.actor} · {formatDate(e.at)}
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}
    </>
  );
}
