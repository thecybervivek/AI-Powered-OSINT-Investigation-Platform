import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/Button";

export function NotFoundPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-slate-50 dark:bg-surface-dark">
      <ShieldAlert className="h-12 w-12 text-slate-400" />
      <h1 className="text-3xl font-bold text-slate-900 dark:text-white">404</h1>
      <p className="text-slate-500 dark:text-slate-400">
        The page you're looking for doesn't exist.
      </p>
      <Link to="/dashboard">
        <Button>Back to Dashboard</Button>
      </Link>
    </div>
  );
}
