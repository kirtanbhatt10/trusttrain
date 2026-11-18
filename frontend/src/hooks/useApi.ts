import { useCallback, useEffect, useRef, useState } from "react";

export interface ApiState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** Load data from an async API call, tracking loading and error state. */
export function useApi<T>(loader: () => Promise<T>, deps: unknown[] = []): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    loaderRef
      .current()
      .then((value) => active && setData(value))
      .catch((err: unknown) => active && setError(err instanceof Error ? err.message : String(err)))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [tick, ...deps]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}

/** Run a mutation, exposing pending/error state. */
export function useAction() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setPending(true);
    setError(null);
    try {
      return await fn();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return undefined;
    } finally {
      setPending(false);
    }
  }, []);
  return { pending, error, run, setError };
}
