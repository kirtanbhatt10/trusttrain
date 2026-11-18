import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Button, Card, EmptyState, ErrorState, Field, Loading, PageHeader, inputClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function ReportView({ title, filename, content, type }: { title: string; filename: string; content: string; type: string }) {
  return (
    <Card title={title} actions={<Button variant="secondary" onClick={() => download(filename, content, type)}>Download</Button>}>
      <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap rounded bg-page p-3 font-mono text-xs text-ink-2">{content}</pre>
    </Card>
  );
}

export function Reports() {
  const [params, setParams] = useSearchParams();
  const incidentId = params.get("incident") ?? "";
  const [datasetId, setDatasetId] = useState("");
  const incidents = useApi(() => api.incidents());
  const datasets = useApi(() => api.datasets());
  const incidentReport = useApi(() => (incidentId ? api.incidentReportMarkdown(incidentId) : Promise.resolve(null)), [incidentId]);
  const datasetReport = useApi(() => (datasetId ? api.datasetReport(datasetId) : Promise.resolve(null)), [datasetId]);

  return (
    <>
      <PageHeader title="Reports" description="Generate investigation reports for incidents (Markdown) and integrity/risk reports for datasets (JSON) from current records." />
      <div className="mb-6 grid gap-4 md:grid-cols-2">
        <Field label="Incident investigation report">
          <select className={inputClass} value={incidentId} onChange={(e) => setParams(e.target.value ? { incident: e.target.value } : {})}>
            <option value="">— select incident —</option>
            {incidents.data?.map((i) => (
              <option key={i.id} value={i.id}>
                {i.title}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Dataset report">
          <select className={inputClass} value={datasetId} onChange={(e) => setDatasetId(e.target.value)}>
            <option value="">— select dataset —</option>
            {datasets.data?.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name} v{d.version}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <div className="space-y-6">
        {!incidentId && !datasetId && <EmptyState title="Choose an incident or dataset to generate a report." />}
        {incidentId &&
          (incidentReport.loading ? (
            <Loading label="Generating incident report…" />
          ) : incidentReport.error ? (
            <ErrorState message={incidentReport.error} onRetry={incidentReport.reload} />
          ) : incidentReport.data ? (
            <ReportView title="Incident report" filename={`incident-${incidentId}.md`} content={incidentReport.data} type="text/markdown" />
          ) : null)}
        {datasetId &&
          (datasetReport.loading ? (
            <Loading label="Generating dataset report…" />
          ) : datasetReport.error ? (
            <ErrorState message={datasetReport.error} onRetry={datasetReport.reload} />
          ) : datasetReport.data ? (
            <ReportView title="Dataset report" filename={`dataset-${datasetId}.json`} content={JSON.stringify(datasetReport.data, null, 2)} type="application/json" />
          ) : null)}
      </div>
    </>
  );
}
