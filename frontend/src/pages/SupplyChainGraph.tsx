import { useState } from "react";
import { LineageGraph } from "../components/LineageGraph";
import { Card, EmptyState, ErrorState, Loading, PageHeader, humanize } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { GraphNode } from "../types";

function Impact({ node }: { node: GraphNode }) {
  const { data, error, loading } = useApi(() => api.downstream(node.ref), [node.ref]);
  if (loading) return <Loading label="Tracing downstream artifacts…" />;
  if (error) return <ErrorState message={error} />;
  if (!data) return null;
  return (
    <div className="space-y-3 text-sm">
      <p>
        <strong>{data.total_affected}</strong> recorded downstream artifact(s) depend on <strong>{node.label}</strong>.
      </p>
      {Object.entries(data.affected).map(([kind, items]) => (
        <div key={kind}>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
            {humanize(kind)} ({items.length})
          </h3>
          <ul className="mt-1 text-ink-2">
            {items.length === 0 ? <li>none</li> : items.map((i) => <li key={i.id}>{i.label}</li>)}
          </ul>
        </div>
      ))}
    </div>
  );
}

export function SupplyChainGraph() {
  const { data, error, loading, reload } = useApi(api.lineage);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  return (
    <>
      <PageHeader
        title="Supply Chain Graph"
        description="Recorded lineage from source datasets through processing, training runs and models to deployments. Edges exist only where a relationship was explicitly recorded."
      />
      {loading && !data ? (
        <Loading />
      ) : error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : !data?.nodes.length ? (
        <EmptyState title="No lineage recorded yet.">Register datasets, training runs and models to build the graph.</EmptyState>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[1fr_20rem]">
          <LineageGraph graph={data} onSelect={(n) => setSelected((s) => (s?.id === n.id ? null : n))} />
          <Card title="Impact analysis">
            {selected?.kind === "dataset" ? (
              <Impact node={selected} />
            ) : (
              <p className="text-sm text-ink-2">Select a dataset node to list every recorded artifact that would be affected if it were compromised.</p>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
