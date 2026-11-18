import { useState } from "react";
import type { Finding } from "../types";
import { Button, SeverityBadge, humanize } from "./ui";

export function FindingCard({ finding, onStatus }: { finding: Finding; onStatus?: (status: Finding["status"]) => void }) {
  const [open, setOpen] = useState(false);
  const rows = finding.evidence.row_indices ?? [];
  const total = finding.evidence.row_indices_total ?? rows.length;
  const { row_indices: _rows, row_indices_total: _total, ...rest } = finding.evidence;
  return (
    <article className="rounded-md border border-line bg-page p-3" aria-label={finding.title}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <h3 className="text-sm font-medium text-ink">{finding.title}</h3>
          </div>
          <p className="mt-1 text-xs text-ink-2">
            {humanize(finding.method)} · confidence {(finding.confidence * 100).toFixed(0)}%{total ? ` · ${total} row(s)` : ""} · {finding.status}
          </p>
        </div>
        <div className="flex gap-2">
          {onStatus && finding.status === "open" && (
            <>
              <Button variant="secondary" onClick={() => onStatus("acknowledged")}>
                Acknowledge
              </Button>
              <Button variant="secondary" onClick={() => onStatus("dismissed")}>
                Dismiss
              </Button>
            </>
          )}
          <Button variant="secondary" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
            {open ? "Hide evidence" : "Evidence"}
          </Button>
        </div>
      </div>
      {open && (
        <div className="mt-3 space-y-3 text-sm">
          <p className="text-ink-2">{finding.explanation}</p>
          {rows.length > 0 && (
            <p className="text-xs text-ink-2">
              Rows (0-based): <span className="font-mono">{rows.join(", ")}</span>
              {total > rows.length && ` … and ${total - rows.length} more`}
            </p>
          )}
          <pre className="max-h-64 overflow-auto rounded bg-surface p-2 text-xs text-ink-2">{JSON.stringify(rest, null, 2)}</pre>
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Suggested investigation</h4>
            <ul className="mt-1 list-disc pl-5 text-ink-2">
              {finding.investigation_steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          </div>
          <p className="text-xs text-muted">
            <strong>Limitations:</strong> {finding.limitations}
          </p>
        </div>
      )}
    </article>
  );
}
