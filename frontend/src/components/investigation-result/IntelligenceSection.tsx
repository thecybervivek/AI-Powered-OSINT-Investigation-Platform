import type { Investigation } from "@/types/investigation";
import { ReverseImageIntelligence } from "./modules/ReverseImageIntelligence";
import { FileIntelligence } from "./modules/FileIntelligence";
import { DomainIntelligence } from "./modules/DomainIntelligence";

interface IntelligenceSectionProps {
  investigation: Investigation;
}

/**
 * Renders a dedicated, module-specific summary above the generic
 * EvidenceList for the modules that have one. Every other module
 * (Username, Email, IP, URL, DNS, Phone, Social Media, Breach,
 * Threat Intelligence, Malware, Composite Risk, Metadata) returns null
 * here and is fully represented by EvidenceList alone - not a
 * regression, since EvidenceList already shows every result for every
 * type. Add a case here only once a module's InvestigationResult.data
 * shape has actually been read from its service.py, the same way
 * Reverse Image, File, and Domain were for this implementation.
 */
export function IntelligenceSection({ investigation }: IntelligenceSectionProps) {
  if (investigation.investigation_type === "reverse_image") {
    return <ReverseImageIntelligence results={investigation.results} />;
  }

  if (investigation.investigation_type === "file") {
    return <FileIntelligence results={investigation.results} />;
  }

  if (investigation.investigation_type === "domain") {
    return <DomainIntelligence results={investigation.results} />;
  }

  return null;
}
