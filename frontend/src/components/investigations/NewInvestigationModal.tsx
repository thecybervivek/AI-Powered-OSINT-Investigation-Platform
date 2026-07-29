import { useEffect, useRef, useState } from "react";
import { ArrowLeft, CheckCircle2 } from "lucide-react";

import { Modal } from "@/components/Modal";
import { Button } from "@/components/Button";
import { useToast } from "@/contexts/ToastContext";
import { investigationService } from "@/services/investigationService";
import { getApiErrorMessage } from "@/utils/apiError";
import type { InvestigationSummary, InvestigationType } from "@/types/investigation";

import { InvestigationTypeSelector } from "./InvestigationTypeSelector";
import { InvestigationInputForm, validateTextTarget } from "./InvestigationInputForm";
import {
  getInvestigationTypeDefinition,
  type InvestigationTypeDefinition,
} from "./investigationTypes.config";
import { assessmentLabelSchema } from "@/utils/validation";

const MIN_COMPOSITE_SELECTIONS = 2;

type Step = "select" | "form" | "success";
type SubmitPhase = "idle" | "uploading" | "starting";

interface NewInvestigationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (id: string) => void;
  /** Preselects a type and skips straight to the form, e.g. from a Dashboard deep link. */
  initialType?: InvestigationType;
}

interface CreatedInvestigationSummary {
  id: string;
  target: string;
  typeLabel: string;
}

export function NewInvestigationModal({
  isOpen,
  onClose,
  onCreated,
  initialType,
}: NewInvestigationModalProps) {
  const { showToast } = useToast();

  const [step, setStep] = useState<Step>("select");
  const [selectedType, setSelectedType] = useState<InvestigationType | null>(null);

  const [value, setValue] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [compositeSelected, setCompositeSelected] = useState<
    Map<string, InvestigationSummary>
  >(new Map());
  const [assessmentLabel, setAssessmentLabel] = useState("");

  const [touched, setTouched] = useState(false);
  const [submitPhase, setSubmitPhase] = useState<SubmitPhase>("idle");
  const [formError, setFormError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreatedInvestigationSummary | null>(null);

  const navigateTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const isSubmitting = submitPhase !== "idle";

  // Reset all transient state whenever the modal is opened, and honor
  // a preselected type (Dashboard deep links, e.g. ?new=true&new_type=file).
  useEffect(() => {
    if (!isOpen) return;

    setValue("");
    setFile(null);
    setCompositeSelected(new Map());
    setAssessmentLabel("");
    setTouched(false);
    setSubmitPhase("idle");
    setFormError(null);
    setCreated(null);

    const initialDefinition = initialType
      ? getInvestigationTypeDefinition(initialType)
      : undefined;

    if (initialDefinition?.available) {
      setSelectedType(initialDefinition.type);
      setStep("form");
    } else {
      setSelectedType(null);
      setStep("select");
    }
  }, [isOpen, initialType]);

  useEffect(() => {
    return () => {
      if (navigateTimer.current) clearTimeout(navigateTimer.current);
    };
  }, []);

  const definition: InvestigationTypeDefinition | null = selectedType
    ? getInvestigationTypeDefinition(selectedType) ?? null
    : null;

  function handleSelectType(type: InvestigationType) {
    setSelectedType(type);
    setValue("");
    setFile(null);
    setCompositeSelected(new Map());
    setAssessmentLabel("");
    setTouched(false);
    setFormError(null);
    setStep("form");
  }

  function handleBackToSelector() {
    setStep("select");
    setFormError(null);
  }

  function handleValueChange(next: string) {
    setTouched(true);
    setValue(next);
  }

  function handleFileChange(next: File | null) {
    setTouched(true);
    setFile(next);
  }

  function handleCompositeChange(next: Map<string, InvestigationSummary>) {
    setTouched(true);
    setCompositeSelected(next);
  }

  function handleAssessmentLabelChange(next: string) {
    setTouched(true);
    setAssessmentLabel(next);
  }

  function computeIsValid(): boolean {
    if (!definition) return false;

    if (definition.inputMode === "file" || definition.inputMode === "image") {
      return file !== null;
    }

    if (definition.inputMode === "composite") {
      return (
        compositeSelected.size >= MIN_COMPOSITE_SELECTIONS &&
        assessmentLabelSchema.safeParse(assessmentLabel).success
      );
    }

    return (
      validateTextTarget(definition.type, value) === null && value.trim().length > 0
    );
  }

  const isValid = computeIsValid();

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();

    if (isSubmitting || !definition) return;

    setTouched(true);
    setFormError(null);

    if (!isValid) return;

    const isUpload = definition.inputMode === "file" || definition.inputMode === "image";
    setSubmitPhase(isUpload ? "uploading" : "starting");

    try {
      let investigationId: string;
      let target: string;

      switch (definition.type) {
        case "username": {
          const result = await investigationService.createUsername(value.trim());
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "email": {
          const result = await investigationService.createEmail(value.trim());
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "domain": {
          const result = await investigationService.createDomain(value.trim());
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "ip_address": {
          const result = await investigationService.createIp(value.trim());
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "dns": {
          const result = await investigationService.createDns(value.trim());
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "url": {
          const result = await investigationService.createUrl(value.trim());
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "phone": {
          const result = await investigationService.createPhone(value.trim());
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "threat_intelligence": {
          const result = await investigationService.createThreatIntelligence(
            value.trim()
          );
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "social_media": {
          const result = await investigationService.createSocialMedia(value.trim());
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "malware": {
          const result = await investigationService.createMalware(
            value.trim().toLowerCase()
          );
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "risk_assessment": {
          const result = await investigationService.createRiskAssessment(
            Array.from(compositeSelected.keys()),
            assessmentLabel.trim() || undefined
          );
          investigationId = result.id;
          target = result.target;
          break;
        }

        case "file": {
          if (!file) throw new Error("Please choose a file.");

          const result = await investigationService.uploadFile(file);
          investigationId = result.investigation.id;
          target = result.investigation.target;
          break;
        }

        case "reverse_image": {
          if (!file) throw new Error("Please choose an image.");

          const result = await investigationService.uploadReverseImage(file);
          investigationId = result.investigation.id;
          target = result.investigation.target;
          break;
        }

        default:
          throw new Error("Unsupported investigation type.");
      }

      setCreated({ id: investigationId, target, typeLabel: definition.label });
      setStep("success");

      showToast("success", "Investigation started.");

      // Real signal, not a fabricated percentage: the investigation
      // was actually created and its id is real. A short pause lets
      // the analyst see the confirmation before we take them away
      // from it, rather than the old behavior of the modal just
      // vanishing with no feedback.
      navigateTimer.current = setTimeout(() => {
        onCreated(investigationId);
      }, 1400);
    } catch (error) {
      setFormError(getApiErrorMessage(error, "Investigation could not be started."));
      setSubmitPhase("idle");
    }
  }

  function handleClose() {
    if (isSubmitting) return;
    onClose();
  }

  const submitLabel =
    submitPhase === "uploading"
      ? "Uploading..."
      : submitPhase === "starting"
      ? "Starting..."
      : "Start Investigation";

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title={step === "success" ? "Investigation Started" : "New Investigation"}
      size="lg"
    >
      {step === "select" && <InvestigationTypeSelector onSelect={handleSelectType} />}

      {step === "form" && definition && (
        <form onSubmit={handleSubmit} className="space-y-4">
          <button
            type="button"
            onClick={handleBackToSelector}
            disabled={isSubmitting}
            className="inline-flex items-center gap-1.5 text-sm font-medium text-slate-500 hover:text-slate-700 disabled:opacity-50 dark:text-slate-400 dark:hover:text-slate-200"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            All investigation types
          </button>

          <div className="flex items-center gap-2">
            <definition.icon className="h-4 w-4 text-brand-600" />
            <h3 className="font-medium text-slate-900 dark:text-white">
              {definition.label}
            </h3>
          </div>

          {formError && (
            <div
              role="alert"
              className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-300"
            >
              {formError}
            </div>
          )}

          <InvestigationInputForm
            definition={definition}
            value={value}
            onValueChange={handleValueChange}
            file={file}
            onFileChange={handleFileChange}
            compositeSelected={compositeSelected}
            onCompositeChange={handleCompositeChange}
            assessmentLabel={assessmentLabel}
            onAssessmentLabelChange={handleAssessmentLabelChange}
            touched={touched}
            disabled={isSubmitting}
          />

          <div className="flex justify-end gap-3 border-t border-slate-100 pt-4 dark:border-slate-800">
            <Button
              type="button"
              variant="ghost"
              onClick={handleClose}
              disabled={isSubmitting}
            >
              Cancel
            </Button>

            <Button type="submit" isLoading={isSubmitting} disabled={isSubmitting || !isValid}>
              {submitLabel}
            </Button>
          </div>
        </form>
      )}

      {step === "success" && created && (
        <div className="space-y-5 text-center">
          <CheckCircle2 className="mx-auto h-10 w-10 text-green-500" />

          <div className="space-y-1 text-left">
            <div className="flex justify-between text-sm">
              <span className="text-slate-500 dark:text-slate-400">Target</span>
              <span className="font-medium text-slate-900 dark:text-white">
                {created.target}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-500 dark:text-slate-400">Type</span>
              <span className="font-medium text-slate-900 dark:text-white">
                {created.typeLabel}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-500 dark:text-slate-400">Status</span>
              <span className="font-medium text-slate-900 dark:text-white">
                Collecting evidence...
              </span>
            </div>
          </div>

          <Button
            className="w-full justify-center"
            onClick={() => {
              if (navigateTimer.current) clearTimeout(navigateTimer.current);
              onCreated(created.id);
            }}
          >
            View Investigation
          </Button>
        </div>
      )}
    </Modal>
  );
}
