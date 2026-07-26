import { Link } from "react-router-dom";
import { ChevronRight } from "lucide-react";

export interface Breadcrumb {
  label: string;
  to?: string;
}

export function Breadcrumbs({ items }: { items: Breadcrumb[] }) {
  return (
    <nav aria-label="Breadcrumb" className="mb-4 flex items-center text-sm">
      {items.map((item, index) => (
        <span key={index} className="flex items-center">
          {index > 0 && (
            <ChevronRight className="mx-1 h-3.5 w-3.5 text-slate-400" />
          )}
          {item.to ? (
            <Link
              to={item.to}
              className="text-slate-500 hover:text-brand-600 dark:text-slate-400 dark:hover:text-brand-400"
            >
              {item.label}
            </Link>
          ) : (
            <span className="font-medium text-slate-900 dark:text-white">
              {item.label}
            </span>
          )}
        </span>
      ))}
    </nav>
  );
}
