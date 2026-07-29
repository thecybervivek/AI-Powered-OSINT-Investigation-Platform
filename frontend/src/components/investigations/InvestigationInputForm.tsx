import type { ZodSchema } from "zod";

import { FileDropZone } from "./FileDropZone";
import { CompositeInvestigationSelector } from "./CompositeInvestigationSelector";
import type { InvestigationTypeDefinition } from "./investigationTypes.config";
import {
  assessmentLabelSchema,
  bareDomainTargetSchema,
  detectHashType,
  domainOrIpTargetSchema,
  emailTargetSchema,
  hostOrIpTargetSchema,
  malwareHashTargetSchema,
  phoneTargetSchema,
  urlTargetSchema,
  usernameTargetSchema,
} from "@/utils/validation";
import type { InvestigationSummary, InvestigationType } from "@/types/investigation";

/**
 * One schema per text-input investigation type, mirroring the actual
 * backend field_validators (see investigationTypes.config.ts header
 * comment / validation.ts for where each one comes from).
 */
const TEXT_SCHEMAS: Partial<Record<InvestigationType, ZodSchema<string>>> = {
  username: usernameTargetSchema,
  social_media: usernameTargetSchema,
  email: emailTargetSchema,
  phone: phoneTargetSchema,
  domain: domainOrIpTargetSchema,
  ip_address: hostOrIpTargetSchema,
  url: urlTargetSchema,
  dns: bareDomainTargetSchema,
  malware: malwareHashTargetSchema,
  threat_intelligence: hostOrIpTargetSchema,
};

export function validateTextTarget(
  type: InvestigationType,
  value: string
): string | null {
  const schema = TEXT_SCHEMAS[type];
  if (!schema) return null;

  const result = schema.safeParse(value);
  return result.success ? null : result.error.issues[0]?.message ?? "Invalid input";
}

interface InvestigationInputFormProps {
  definition: InvestigationTypeDefinition;
  value: string;
  onValueChange: (value: string) => void;
  file: File | null;
  onFileChange: (file: File | null) => void;
  compositeSelected: Map<string, InvestigationSummary>;
  onCompositeChange: (next: Map<string, InvestigationSummary>) => void;
  assessmentLabel: string;
  onAssessmentLabelChange: (label: string) => void;
  touched: boolean;
  disabled?: boolean;
}

export function InvestigationInputForm({
  definition,
  value,
  onValueChange,
  file,
  onFileChange,
  compositeSelected,
  onCompositeChange,
  assessmentLabel,
  onAssessmentLabelChange,
  touched,
  disabled,
}: InvestigationInputFormProps) {
  if (definition.inputMode === "file" || definition.inputMode === "image") {
    return (
      <FileDropZone
        file={file}
        onFileSelect={onFileChange}
        kind={definition.inputMode === "image" ? "image" : "file"}
        disabled={disabled}
      />
    );
  }

  if (definition.inputMode === "composite") {
    const labelError = assessmentLabelSchema.safeParse(assessmentLabel);

    return (
      <div className="space-y-4">
        <div>
          <label
            htmlFor="assessment-label"
            className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300"
          >
            Assessment Name
          </label>
          <input
            id="assessment-label"
            value={assessmentLabel}
            onChange={(event) => onAssessmentLabelChange(event.target.value)}
            placeholder="Composite Risk Assessment"
            disabled={disabled}
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
          />
          {touched && !labelError.success && (
            <p role="alert" className="mt-1 text-xs text-red-600 dark:text-red-400">
              {labelError.error.issues[0]?.message}
            </p>
          )}
        </div>

        <CompositeInvestigationSelector
          selected={compositeSelected}
          onChange={onCompositeChange}
          disabled={disabled}
        />
      </div>
    );
  }

  // Text-input types.
  const hashType =
    definition.type === "malware" ? detectHashType(value) : null;

  const error = touched ? validateTextTarget(definition.type, value) : null;

  const inputId = `investigation-target-${definition.type}`;

  return (
    <div>
      <label
        htmlFor={inputId}
        className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300"
      >
        {definition.inputLabel ?? "Target"}
      </label>

      <input
        id={inputId}
        value={value}
        onChange={(event) => onValueChange(event.target.value)}
        placeholder={definition.placeholder}
        disabled={disabled}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? `${inputId}-error` : undefined}
        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
      />

      {definition.type === "malware" && value.trim() && !error && (
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          Detected: <span className="font-medium">{hashType}</span>
        </p>
      )}

      {error ? (
        <p
          id={`${inputId}-error`}
          role="alert"
          className="mt-1 text-xs text-red-600 dark:text-red-400"
        >
          {error}
        </p>
      ) : (
        definition.helperText && (
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {definition.helperText}
          </p>
        )
      )}
    </div>
  );
}
