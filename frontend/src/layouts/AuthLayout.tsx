import { Outlet } from "react-router-dom";
import { ShieldAlert } from "lucide-react";

export function AuthLayout() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 px-4 dark:bg-surface-dark">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center gap-2">
          <ShieldAlert className="h-10 w-10 text-brand-600" />
          <h1 className="text-lg font-semibold text-slate-900 dark:text-white">
            AI-Powered OSINT Investigation Platform
          </h1>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-surface-darkAlt">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
