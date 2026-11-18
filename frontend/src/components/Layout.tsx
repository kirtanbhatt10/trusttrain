import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";

export const NAV = [
  { to: "/", label: "Overview" },
  { to: "/datasets", label: "Dataset Inventory" },
  { to: "/inspection", label: "Dataset Inspection" },
  { to: "/findings", label: "Security Findings" },
  { to: "/evaluation", label: "Model Evaluation" },
  { to: "/supply-chain", label: "Supply Chain Graph" },
  { to: "/training", label: "Training Runs" },
  { to: "/incidents", label: "Security Incidents" },
  { to: "/reports", label: "Reports" },
  { to: "/settings", label: "Settings" },
];

export function Layout() {
  const { user, logout } = useAuth();
  return (
    <div className="flex min-h-full flex-col md:flex-row">
      <aside className="border-b border-line bg-surface md:sticky md:top-0 md:h-screen md:w-60 md:shrink-0 md:border-b-0 md:border-r">
        <div className="flex items-center gap-2 px-5 py-4">
          <span aria-hidden className="grid h-7 w-7 place-items-center rounded-md bg-accent-strong text-sm font-bold text-white">T</span>
          <span className="font-semibold tracking-tight">TrustTrain</span>
        </div>
        <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-col md:overflow-visible">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `whitespace-nowrap rounded-md px-3 py-2 text-sm ${isActive ? "bg-raised font-medium text-ink" : "text-ink-2 hover:bg-raised/60 hover:text-ink"}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        {user && (
          <div className="hidden border-t border-line px-5 py-3 text-xs text-ink-2 md:absolute md:bottom-0 md:block md:w-60">
            <div className="truncate text-ink">{user.email}</div>
            <div className="mt-0.5 flex items-center justify-between">
              <span className="capitalize">{user.role}</span>
              <button onClick={logout} className="underline underline-offset-2 hover:text-ink">
                Sign out
              </button>
            </div>
          </div>
        )}
      </aside>
      <main className="min-w-0 flex-1 px-4 py-6 md:px-8">
        <Outlet />
      </main>
    </div>
  );
}
