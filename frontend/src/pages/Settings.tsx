import type { FormEvent } from "react";
import { Button, Card, ErrorState, Field, Loading, Mono, PageHeader, Table, formatBytes, formatDate, humanize, inputClass } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";
import type { Role } from "../types";

function Users() {
  const users = useApi(api.users);
  const action = useAction();
  const create = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    if (await action.run(() => api.createUser({ email: String(f.get("email")), password: String(f.get("password")), role: f.get("role") as Role }))) {
      form.reset();
      users.reload();
    }
  };
  return (
    <Card title="Users">
      <form onSubmit={create} className="mb-4 grid gap-3 md:grid-cols-4" aria-label="Create user">
        <Field label="Email">
          <input name="email" type="email" required className={inputClass} />
        </Field>
        <Field label="Password" hint="At least 12 characters.">
          <input name="password" type="password" required minLength={12} autoComplete="new-password" className={inputClass} />
        </Field>
        <Field label="Role">
          <select name="role" className={inputClass} defaultValue="viewer">
            <option value="viewer">Viewer</option>
            <option value="analyst">Analyst</option>
            <option value="admin">Admin</option>
          </select>
        </Field>
        <div className="flex items-end">
          <Button type="submit" disabled={action.pending}>
            Add user
          </Button>
        </div>
      </form>
      {action.error && <ErrorState message={action.error} />}
      {users.loading && !users.data ? (
        <Loading />
      ) : users.error ? (
        <ErrorState message={users.error} />
      ) : (
        <Table head={["Email", "Role", "Created"]}>
          {users.data?.map((u) => (
            <tr key={u.id}>
              <td className="px-3 py-2">{u.email}</td>
              <td className="px-3 py-2 capitalize">{u.role}</td>
              <td className="px-3 py-2 text-xs text-ink-2">{formatDate(u.created_at)}</td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

export function Settings() {
  const { can } = useAuth();
  const settings = useApi(api.settings);
  const activity = useApi(() => api.activity(50));
  const s = settings.data;
  return (
    <>
      <PageHeader title="Settings" description="Server configuration (read-only from the dashboard; change it through environment variables), users and the audit log." />
      {settings.loading && !s ? (
        <Loading />
      ) : settings.error ? (
        <ErrorState message={settings.error} onRetry={settings.reload} />
      ) : s ? (
        <div className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-2">
            <Card title="Processing limits and detectors">
              <dl className="grid grid-cols-[12rem_1fr] gap-y-2 text-sm">
                <dt className="text-muted">Environment</dt>
                <dd>{s.environment}</dd>
                <dt className="text-muted">Max upload</dt>
                <dd>{formatBytes(s.limits.max_upload_bytes)}</dd>
                <dt className="text-muted">Max rows</dt>
                <dd>{s.limits.max_rows.toLocaleString()}</dd>
                <dt className="text-muted">Max text per cell</dt>
                <dd>{s.limits.max_text_chars_per_cell.toLocaleString()} characters</dd>
                <dt className="text-muted">Rate limit</dt>
                <dd>{s.rate_limit_per_minute} requests/min per client</dd>
                <dt className="text-muted">Formats</dt>
                <dd>{s.supported_formats.join(", ")}</dd>
                <dt className="text-muted">Detectors</dt>
                <dd>{s.detectors.map(humanize).join(", ")}</dd>
                {Object.entries(s.thresholds).map(([k, v]) => (
                  <div key={k} className="contents">
                    <dt className="text-muted">{humanize(k)}</dt>
                    <dd className="tabular-nums">{v}</dd>
                  </div>
                ))}
              </dl>
            </Card>
            <Card title="Provenance signing key">
              <p className="text-sm text-ink-2">
                {s.signing_key.algorithm} · fingerprint <Mono>{s.signing_key.fingerprint}</Mono>
              </p>
              <pre className="mt-3 overflow-auto rounded bg-page p-3 font-mono text-xs text-ink-2">{s.signing_key.public_key_pem}</pre>
              <p className="mt-2 text-xs text-muted">Share the public key so others can verify exported manifests. The private key never leaves the server.</p>
            </Card>
          </div>
          {can("admin") && <Users />}
          <Card title="Audit log">
            {activity.loading && !activity.data ? (
              <Loading />
            ) : activity.error ? (
              <ErrorState message={activity.error} />
            ) : (
              <Table head={["Time", "Actor", "Action", "Summary"]} empty={activity.data?.length === 0}>
                {activity.data?.map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2">{formatDate(e.at)}</td>
                    <td className="px-3 py-2">{e.actor}</td>
                    <td className="px-3 py-2 font-mono text-xs">{e.action}</td>
                    <td className="px-3 py-2 text-ink-2">{e.summary}</td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
        </div>
      ) : null}
    </>
  );
}
