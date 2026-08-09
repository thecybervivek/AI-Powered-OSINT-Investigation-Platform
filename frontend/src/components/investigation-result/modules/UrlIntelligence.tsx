import React from "react";
import { Globe, Shield, ExternalLink, AlertTriangle } from "lucide-react";
import type { InvestigationResult } from "@/types/investigation";

interface UrlIntelligenceProps {
  data?: any;
  results?: InvestigationResult[];
}

export const UrlIntelligence: React.FC<UrlIntelligenceProps> = ({
  data,
  results,
}) => {
  if (!data && !results) return null;

  const resultData =
    data ??
    results?.find((result) => result.source === "url_intelligence")?.data ??
    {};

  const urlData = resultData.url_intelligence || resultData;
  const vt = urlData.virustotal;

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-500/10 text-blue-400 rounded-lg">
              <Globe className="w-5 h-5" />
            </div>
            <div className="truncate">
              <p className="text-sm font-medium text-slate-400">Target URL</p>
              <p className="text-sm font-semibold text-slate-100 truncate">{urlData.url || 'N/A'}</p>
            </div>
          </div>
        </div>

        {vt && vt.stats && (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-purple-500/10 text-purple-400 rounded-lg">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-400">Detections</p>
                <p className="text-2xl font-semibold text-slate-100">
                  {Object.values(vt.stats).reduce((sum: number, val: any) => sum + val, 0) > 0
                    ? `${vt.stats.malicious + vt.stats.suspicious} / ${Object.values(vt.stats).reduce((sum: number, val: any) => sum + val, 0)}`
                    : '0'}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* URL Analysis Details */}
      {urlData.categories && (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 space-y-3">
          <h4 className="text-sm font-medium text-slate-300">Categories</h4>
          <div className="flex flex-wrap gap-2">
            {Object.entries(urlData.categories).map(([key, val]: [string, any]) => (
              <span key={key} className="px-2.5 py-1 bg-slate-700/50 text-slate-300 rounded-md text-xs">
                {key}: {String(val)}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};