import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { RiskLevel, Severity } from "../types";

// Status colours always travel with a text label (never colour alone).
const TONE: Record<string, { dot: string; text: string; border: string }> = {
  critical: { dot: "bg-critical", text: "text-ink", border: "border-critical/60" },
  high: { dot: "bg-serious", text: "text-ink", border: "border-serious/60" },
  medium: { dot: "bg-warning", text: "text-ink", border: "border-warning/50" },
  low: { dot: "bg-accent", text: "text-ink", border: "border-accent/50" },
  info: { dot: "bg-muted", text: "text-ink-2", border: "border-line" },
  none: { dot: "bg-good", text: "text-ink", border: "border-good/50" },
  unknown: { dot: "bg-muted", text: "text-ink-2", border: "border-line" },
  verified: { dot: "bg-good", text: "text-ink", border: "border-good/50" },
  modified: { dot: "bg-critical", text: "text-ink", border: "border-critical/60" },
  unverified: { dot: "bg-muted", text: "text-ink-2", border: "border-line" },
  quarantined: { dot: "bg-critical", text: "text-ink", border: "border-critical/60" },
  active: { dot: "bg-good", text: "text-ink", border: "border-good/50" },
  approved: { dot: "bg-good", text: "text-ink", border: "border-good/50" },
  rejected: { dot: "bg-critical", text: "text-ink", border: "border-critical/60" },
  pending: { dot: "bg-warning", text: "text-ink", border: "border-warning/50" },
  open: { dot: "bg-serious", text: "text-ink", border: "border-serious/60" },
  under_investigation: { dot: "bg-warning", text: "text-ink", border: "border-warning/50" },
  remediation_required: { dot: "bg-serious", text: "text-ink", border: "border-serious/60" },
  resolved: { dot: "bg-good", text: "text-ink", border: "border-good/50" },
};

export function humanize(value: string): string {
  return value.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export function Badge({ value, label }: { value: string; label?: string }) {
  const tone = TONE[value] ?? TONE.unknown;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${tone.border} ${tone.text}`}>
      <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} />
      {label ?? humanize(value)}
    </span>
  );
}

export const SeverityBadge = ({ severity }: { severity: Severity }) => <Badge value={severity} />;
export const RiskBadge = ({ risk }: { risk: RiskLevel }) => <Badge value={risk} label={risk === "none" ? "No findings" : humanize(risk)} />;

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-line bg-surface ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          {title && <h2 className="text-sm font-semibold text-ink">{title}</h2>}
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-ink-2">{description}</p>}
      </div>
      {actions && <div className="flex gap-2">{actions}</div>}
    </div>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums text-ink">{value}</div>
      {hint && <div className="mt-1 text-xs text-ink-2">{hint}</div>}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 py-8 text-sm text-ink-2">
      <span aria-hidden className="h-3 w-3 animate-spin rounded-full border-2 border-line border-t-accent" />
      {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded-lg border border-critical/60 bg-critical/10 p-4 text-sm text-ink">
      <strong className="font-semibold">Something went wrong.</strong> {message}
      {onRetry && (
        <button onClick={onRetry} className="ml-3 underline underline-offset-2 hover:text-accent">
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-line px-6 py-10 text-center">
      <p className="text-sm font-medium text-ink">{title}</p>
      {children && <div className="mt-1 text-sm text-ink-2">{children}</div>}
    </div>
  );
}

export function Button({ variant = "primary", className = "", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  const styles = {
    primary: "bg-accent-strong text-white hover:bg-accent",
    secondary: "border border-line bg-raised text-ink hover:border-muted",
    danger: "border border-critical/70 bg-critical/15 text-ink hover:bg-critical/25",
  }[variant];
  return (
    <button
      {...props}
      className={`inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${styles} ${className}`}
    />
  );
}

export const inputClass =
  "w-full rounded-md border border-line bg-page px-3 py-1.5 text-sm text-ink placeholder:text-muted focus:border-accent focus:outline-none";

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block font-medium text-ink-2">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export function Table({ head, children, empty }: { head: string[]; children: ReactNode; empty?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-line text-xs uppercase tracking-wide text-muted">
            {head.map((h) => (
              <th key={h} scope="col" className="px-3 py-2 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-line/60">{children}</tbody>
      </table>
      {empty && <p className="px-3 py-6 text-center text-sm text-ink-2">Nothing to show yet.</p>}
    </div>
  );
}

export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <code title={title} className="font-mono text-xs text-ink-2">
      {children}
    </code>
  );
}

export const shortHash = (hash: string) => (hash ? `${hash.slice(0, 12)}…` : "—");
export const formatDate = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
export const formatBytes = (n: number) =>
  n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 ** 2).toFixed(1)} MB`;
