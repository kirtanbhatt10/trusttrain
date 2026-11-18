import { useState, type FormEvent } from "react";
import { Button, Field, inputClass } from "../components/ui";
import { useAuth } from "../hooks/useAuth";

export function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setPending(true);
    setError(null);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="grid min-h-full place-items-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-lg border border-line bg-surface p-6" aria-label="Sign in">
        <div>
          <h1 className="text-lg font-semibold">Sign in to TrustTrain</h1>
          <p className="mt-1 text-sm text-ink-2">AI training supply chain security</p>
        </div>
        <Field label="Email">
          <input className={inputClass} type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field label="Password">
          <input className={inputClass} type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        {error && (
          <p role="alert" className="text-sm text-critical">
            {error}
          </p>
        )}
        <Button type="submit" disabled={pending} className="w-full">
          {pending ? "Signing in…" : "Sign in"}
        </Button>
      </form>
    </div>
  );
}
