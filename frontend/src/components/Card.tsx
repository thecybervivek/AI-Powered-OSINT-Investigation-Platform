import type { HTMLAttributes, ReactNode } from "react";
import clsx from "clsx";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
}

export function Card({ children, className, ...props }: CardProps) {
  return (
    <div
      className={clsx(
        "rounded-xl border border-slate-200 bg-white p-5 shadow-sm",
        "dark:border-slate-800 dark:bg-surface-darkAlt",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: string | number;
  icon: ReactNode;
  accent?: "brand" | "risk-low" | "risk-medium" | "risk-high" | "risk-critical";
}

const accentClasses: Record<NonNullable<StatCardProps["accent"]>, string> = {
  brand: "bg-brand-100 text-brand-700 dark:bg-brand-900/40 dark:text-brand-300",
  "risk-low": "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300",
  "risk-medium": "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300",
  "risk-high": "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300",
  "risk-critical": "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300",
};

export function StatCard({ label, value, icon, accent = "brand" }: StatCardProps) {
  return (
    <Card className="flex items-center gap-4">
      <div className={clsx("rounded-lg p-3", accentClasses[accent])}>{icon}</div>
      <div>
        <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
        <p className="text-2xl font-semibold text-slate-900 dark:text-white">
          {value}
        </p>
      </div>
    </Card>
  );
}
