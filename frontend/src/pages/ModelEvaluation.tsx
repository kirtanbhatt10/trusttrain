import { useState, type FormEvent } from "react";
import { Badge, Button, Card, EmptyState, ErrorState, Field, Loading, PageHeader, Table, formatDate, humanize, inputClass } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";
import type { Evaluation } from "../types";

const VERDICT_TONE: Record<Evaluation["classification"], string> = {
  confirmed_experimental_trigger: "critical",
  suspicious_behavior_detected: "high",
  unverified_potential_backdoor: "medium",
  no_trigger_behavior_detected: "none",
};
const pct = (v: number | null | undefined) => (v == null ? "—" : `${(v * 100).toFixed(1)}%`);

function EvaluationDetail({ evaluation, modelName }: { evaluation: Evaluation; modelName: (id: string | null) => string }) {
  const r = evaluation.results;
  const triggers = [...r.declared_triggers.filter((t) => t.flip_rate > 0), ...r.suspicious_triggers, ...r.weak_signals];
  const unique = triggers.filter((t, i) => triggers.findIndex((o) => o.token === t.token && o.target === t.target) === i);
  return (
    <div className="space-y-3 text-sm">
      <div className="flex flex-wrap items-center gap-3">
        <Badge value={VERDICT_TONE[evaluation.classification]} label={humanize(evaluation.classification)} />
        <span className="text-ink-2">
          {modelName(evaluation.model_id)}
          {evaluation.comparison_model_id && ` vs ${modelName(evaluation.comparison_model_id)}`} · baseline accuracy {pct(r.baseline.accuracy)} on{" "}
          {r.baseline.n} examples · {r.control.tokens_tested} candidate tokens · {evaluation.duration_ms} ms
        </span>
      </div>
      {unique.length > 0 ? (
        <Table head={["Token", "Target label", "Flip rate", "Robust z", "Comparison model flip rate"]}>
          {unique.map((t) => {
            const cmp = r.comparison?.trigger_flip_rates.find((c) => c.token === t.token && c.target === t.target);
            return (
              <tr key={`${t.token}-${t.target}`}>
                <td className="px-3 py-1.5 font-mono">{t.token}</td>
                <td className="px-3 py-1.5">{t.target}</td>
                <td className="px-3 py-1.5 tabular-nums">{pct(t.flip_rate)}</td>
                <td className="px-3 py-1.5 tabular-nums">{t.z_score.toFixed(1)}</td>
                <td className="px-3 py-1.5 tabular-nums">{cmp ? pct(cmp.comparison_flip_rate) : "—"}</td>
              </tr>
            );
          })}
        </Table>
      ) : (
        <p className="text-ink-2">No tested token changed predictions more than the probe population (median flip {pct(r.control.median_flip_rate)}).</p>
      )}
      {r.comparison && (
        <p className="text-ink-2">
          Behaviour regression: <strong className="text-ink">{r.comparison.behavior_regression.passed ? "passed" : "failed"}</strong> — prediction
          agreement {pct(r.comparison.prediction_agreement)}, accuracy delta {(r.comparison.accuracy_delta * 100).toFixed(1)} pts (
          {r.comparison.behavior_regression.criteria}).
        </p>
      )}
      <ul className="list-disc pl-5 text-xs text-muted">
        {r.limitations.map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>
    </div>
  );
}

export function ModelEvaluation() {
  const { can } = useAuth();
  const models = useApi(api.models);
  const datasets = useApi(() => api.datasets());
  const evaluations = useApi(api.evaluations);
  const action = useAction();
  const [selected, setSelected] = useState<string | null>(null);
  const labModels = models.data?.filter((m) => m.kind === "lab") ?? [];
  const modelName = (id: string | null) => models.data?.find((m) => m.id === id)?.name ?? "unknown model";

  const train = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const ok = await action.run(() => api.trainLabModel({ name: String(f.get("name")), dataset_id: String(f.get("dataset_id")), epochs: Number(f.get("epochs")) }));
    if (ok) models.reload();
  };
  const evaluate = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const triggers = String(f.get("triggers") ?? "").split(",").map((t) => t.trim()).filter(Boolean);
    const result = await action.run(() =>
      api.runEvaluation({
        model_id: String(f.get("model_id")),
        dataset_id: String(f.get("dataset_id")),
        comparison_model_id: String(f.get("comparison_model_id") || "") || null,
        declared_triggers: triggers,
      }),
    );
    if (result) {
      setSelected(result.id);
      evaluations.reload();
    }
  };

  const datasetOptions = datasets.data?.map((d) => (
    <option key={d.id} value={d.id}>
      {d.name} v{d.version}
    </option>
  ));

  return (
    <>
      <PageHeader
        title="Model Evaluation"
        description="Backdoor Discovery Lab: controlled trigger-insertion tests on isolated TrustTrain lab models. Registered external checkpoints are tracked for lineage only."
      />
      {action.error && <ErrorState message={action.error} />}
      {can("analyst") && (
        <div className="mb-6 grid gap-6 lg:grid-cols-2">
          <Card title="Train an experimental lab model">
            <form onSubmit={train} className="space-y-3">
              <Field label="Model name">
                <input name="name" required className={inputClass} maxLength={200} />
              </Field>
              <Field label="Training dataset" hint="Needs text and label columns. Quarantined datasets are refused.">
                <select name="dataset_id" required className={inputClass}>
                  {datasetOptions}
                </select>
              </Field>
              <Field label="Epochs">
                <input name="epochs" type="number" min={1} max={50} defaultValue={12} className={inputClass} />
              </Field>
              <Button type="submit" disabled={action.pending || !datasets.data?.length}>
                Train lab model
              </Button>
            </form>
          </Card>
          <Card title="Run backdoor evaluation">
            <form onSubmit={evaluate} className="space-y-3">
              <Field label="Model under test">
                <select name="model_id" required className={inputClass}>
                  {labModels.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Clean evaluation dataset">
                <select name="dataset_id" required className={inputClass}>
                  {datasetOptions}
                </select>
              </Field>
              <Field label="Comparison (clean) model — optional">
                <select name="comparison_model_id" className={inputClass}>
                  <option value="">— none —</option>
                  {labModels.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Declared experimental triggers" hint="Comma-separated. Only declared triggers on lab models can be 'confirmed'.">
                <input name="triggers" className={inputClass} placeholder="e.g. cf" />
              </Field>
              <Button type="submit" disabled={action.pending || labModels.length === 0}>
                {action.pending ? "Evaluating…" : "Evaluate"}
              </Button>
            </form>
          </Card>
        </div>
      )}
      <Card title="Evaluation results">
        {evaluations.loading && !evaluations.data ? (
          <Loading />
        ) : evaluations.error ? (
          <ErrorState message={evaluations.error} onRetry={evaluations.reload} />
        ) : !evaluations.data?.length ? (
          <EmptyState title="No evaluations yet." />
        ) : (
          <ul className="divide-y divide-line/60">
            {evaluations.data.map((ev) => (
              <li key={ev.id} className="py-3">
                <button className="flex w-full flex-wrap items-center justify-between gap-2 text-left" aria-expanded={selected === ev.id} onClick={() => setSelected(selected === ev.id ? null : ev.id)}>
                  <span className="flex items-center gap-3">
                    <Badge value={VERDICT_TONE[ev.classification]} label={humanize(ev.classification)} />
                    <span className="text-sm text-ink">{modelName(ev.model_id)}</span>
                  </span>
                  <span className="text-xs text-ink-2">{formatDate(ev.created_at)}</span>
                </button>
                {selected === ev.id && (
                  <div className="mt-3">
                    <EvaluationDetail evaluation={ev} modelName={modelName} />
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
