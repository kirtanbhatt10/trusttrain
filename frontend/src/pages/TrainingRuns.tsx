import { useState, type FormEvent } from "react";
import { Badge, Button, Card, ErrorState, Field, Loading, Mono, PageHeader, Table, formatDate, inputClass, shortHash } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";

export function TrainingRuns() {
  const { can } = useAuth();
  const runs = useApi(api.trainingRuns);
  const models = useApi(api.models);
  const deployments = useApi(api.deployments);
  const datasets = useApi(() => api.datasets());
  const action = useAction();
  const [runDatasets, setRunDatasets] = useState<string[]>([]);
  const dsName = (id: string) => {
    const d = datasets.data?.find((x) => x.id === id);
    return d ? `${d.name} v${d.version}` : id;
  };
  const reloadAll = () => {
    runs.reload();
    models.reload();
    deployments.reload();
  };

  const createRun = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    if (await action.run(() => api.createTrainingRun({ name: String(f.get("name")), dataset_ids: runDatasets, notes: String(f.get("notes") ?? "") }))) {
      form.reset();
      setRunDatasets([]);
      reloadAll();
    }
  };
  const registerModel = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    const origin = String(f.get("origin"));
    const [type, id] = origin.split(":");
    const body = {
      name: String(f.get("name")),
      version: String(f.get("version") || "1"),
      kind: type === "model" ? "fine_tuned" : "checkpoint",
      training_run_id: type === "run" ? id : null,
      parent_model_id: type === "model" ? id : null,
    };
    if (await action.run(() => api.registerModel(body))) {
      form.reset();
      reloadAll();
    }
  };
  const deploy = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    if (await action.run(() => api.createDeployment({ model_id: String(f.get("model_id")), environment: String(f.get("environment")), endpoint: String(f.get("endpoint") ?? "") }))) {
      form.reset();
      reloadAll();
    }
  };

  const loading = (runs.loading && !runs.data) || (models.loading && !models.data);
  const error = runs.error || models.error || deployments.error;

  return (
    <>
      <PageHeader title="Training Runs" description="Record which dataset versions trained which models, and where those models are deployed. These records drive lineage and recall." />
      {action.error && <ErrorState message={action.error} />}
      {can("analyst") && (
        <div className="mb-6 grid gap-6 lg:grid-cols-3">
          <Card title="Record training run">
            <form onSubmit={createRun} className="space-y-3">
              <Field label="Run name">
                <input name="name" required className={inputClass} maxLength={200} />
              </Field>
              <Field label="Training datasets" hint="Hold Ctrl/Cmd to select several.">
                <select
                  multiple
                  required
                  className={`${inputClass} h-24`}
                  value={runDatasets}
                  onChange={(e) => setRunDatasets(Array.from(e.target.selectedOptions, (o) => o.value))}
                >
                  {datasets.data?.map((d) => (
                    <option key={d.id} value={d.id} disabled={d.quarantined}>
                      {d.name} v{d.version}
                      {d.quarantined ? " (quarantined)" : ""}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Notes">
                <input name="notes" className={inputClass} maxLength={5000} />
              </Field>
              <Button type="submit" disabled={action.pending || runDatasets.length === 0}>
                Record run
              </Button>
            </form>
          </Card>
          <Card title="Register model artifact">
            <form onSubmit={registerModel} className="space-y-3">
              <Field label="Model name">
                <input name="name" required className={inputClass} maxLength={200} />
              </Field>
              <Field label="Version">
                <input name="version" defaultValue="1" className={inputClass} maxLength={64} />
              </Field>
              <Field label="Produced by" hint="A training run, or a parent model for fine-tunes.">
                <select name="origin" required className={inputClass}>
                  {runs.data?.map((r) => (
                    <option key={r.id} value={`run:${r.id}`}>
                      Run: {r.name}
                    </option>
                  ))}
                  {models.data?.map((m) => (
                    <option key={m.id} value={`model:${m.id}`}>
                      Fine-tune of: {m.name} v{m.version}
                    </option>
                  ))}
                </select>
              </Field>
              <Button type="submit" disabled={action.pending || !(runs.data?.length || models.data?.length)}>
                Register model
              </Button>
            </form>
          </Card>
          <Card title="Record deployment">
            <form onSubmit={deploy} className="space-y-3">
              <Field label="Model">
                <select name="model_id" required className={inputClass}>
                  {models.data
                    ?.filter((m) => m.status !== "quarantined")
                    .map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.name} v{m.version}
                      </option>
                    ))}
                </select>
              </Field>
              <Field label="Environment">
                <input name="environment" required className={inputClass} placeholder="production" maxLength={64} />
              </Field>
              <Field label="Endpoint">
                <input name="endpoint" className={inputClass} placeholder="https://…" maxLength={500} />
              </Field>
              <Button type="submit" disabled={action.pending || !models.data?.length}>
                Record deployment
              </Button>
            </form>
          </Card>
        </div>
      )}
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState message={error} onRetry={reloadAll} />
      ) : (
        <div className="space-y-6">
          <Card title="Training runs">
            <Table head={["Run", "Datasets", "Status", "Recorded"]} empty={runs.data?.length === 0}>
              {runs.data?.map((r) => (
                <tr key={r.id}>
                  <td className="px-3 py-2 font-medium">{r.name}</td>
                  <td className="px-3 py-2 text-ink-2">{r.dataset_ids.map(dsName).join(", ")}</td>
                  <td className="px-3 py-2">{r.status}</td>
                  <td className="px-3 py-2 text-xs text-ink-2">{formatDate(r.created_at)}</td>
                </tr>
              ))}
            </Table>
          </Card>
          <Card title="Models">
            <Table head={["Model", "Kind", "Produced by", "SHA-256", "Status", "Deployments"]} empty={models.data?.length === 0}>
              {models.data?.map((m) => (
                <tr key={m.id}>
                  <td className="px-3 py-2 font-medium">
                    {m.name} <span className="text-ink-2">v{m.version}</span>
                  </td>
                  <td className="px-3 py-2">{m.kind.replace("_", " ")}</td>
                  <td className="px-3 py-2 text-ink-2">
                    {m.training_run_id ? runs.data?.find((r) => r.id === m.training_run_id)?.name : models.data?.find((p) => p.id === m.parent_model_id)?.name}
                  </td>
                  <td className="px-3 py-2">
                    <Mono title={m.sha256}>{shortHash(m.sha256)}</Mono>
                  </td>
                  <td className="px-3 py-2">
                    <Badge value={m.status} />
                  </td>
                  <td className="px-3 py-2 text-ink-2">
                    {deployments.data?.filter((d) => d.model_id === m.id).map((d) => d.environment).join(", ") || "—"}
                  </td>
                </tr>
              ))}
            </Table>
          </Card>
        </div>
      )}
    </>
  );
}
