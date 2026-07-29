import { useId, useRef, useState } from "react";
import type { DragEvent } from "react";
import { CheckCircle2, Upload, X } from "lucide-react";
import clsx from "clsx";

import { formatBytes } from "@/utils/formatters";

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // Mirrors backend FILE_UPLOAD_MAX_SIZE_MB (50 MB).

const IMAGE_EXTENSIONS = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"];
const IMAGE_ACCEPT = "image/jpeg,image/png,image/gif,image/bmp,image/tiff,image/webp";

interface FileDropZoneProps {
  file: File | null;
  onFileSelect: (file: File | null) => void;
  kind: "file" | "image";
  disabled?: boolean;
}

/**
 * Client-side hints (accepted extensions, size ceiling) mirror the
 * backend's actual limits, but they are hints, not the source of
 * truth - `validate_upload()` on the server re-checks magic bytes,
 * size, and extension regardless of what the browser reports here.
 */
export function FileDropZone({ file, onFileSelect, kind, disabled }: FileDropZoneProps) {
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [clientError, setClientError] = useState<string | null>(null);

  const isImage = kind === "image";

  function validateAndSet(selected: File | null) {
    setClientError(null);

    if (!selected) {
      onFileSelect(null);
      return;
    }

    if (selected.size === 0) {
      setClientError("Selected file is empty.");
      onFileSelect(null);
      return;
    }

    if (selected.size > MAX_UPLOAD_BYTES) {
      setClientError(`File exceeds the 50 MB upload limit.`);
      onFileSelect(null);
      return;
    }

    if (isImage) {
      const lowerName = selected.name.toLowerCase();
      const looksLikeImage =
        selected.type.startsWith("image/") ||
        IMAGE_EXTENSIONS.some((ext) => lowerName.endsWith(ext));

      if (!looksLikeImage) {
        setClientError(
          "Selected file doesn't look like a supported image (JPEG, PNG, GIF, BMP, TIFF, WEBP)."
        );
        onFileSelect(null);
        return;
      }
    }

    onFileSelect(selected);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragging(false);

    if (disabled) return;

    const dropped = event.dataTransfer.files?.[0] ?? null;
    validateAndSet(dropped);
  }

  function handleRemove() {
    setClientError(null);
    onFileSelect(null);

    if (inputRef.current) {
      inputRef.current.value = "";
    }
  }

  return (
    <div>
      <label
        htmlFor={inputId}
        className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300"
      >
        {isImage ? "Image" : "File"}
      </label>

      {!file ? (
        <div
          onDragOver={(event) => {
            event.preventDefault();
            if (!disabled) setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          className={clsx(
            "flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-4 py-8 text-center text-sm transition-colors",
            isDragging
              ? "border-brand-500 bg-brand-50 dark:bg-brand-900/10"
              : "border-slate-300 dark:border-slate-700",
            disabled
              ? "cursor-not-allowed opacity-60"
              : "cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800"
          )}
          onClick={() => !disabled && inputRef.current?.click()}
        >
          <Upload className="h-6 w-6 text-slate-400" />

          <p className="text-slate-600 dark:text-slate-300">
            <span className="font-medium text-brand-600">Drop file here</span>
            <br />
            or{" "}
            <span className="font-medium text-brand-600 underline">
              Browse Files
            </span>
          </p>

          {isImage && (
            <p className="text-xs text-slate-400">
              Supported: JPEG, PNG, GIF, BMP, TIFF, WEBP · up to 50 MB
            </p>
          )}
          {!isImage && (
            <p className="text-xs text-slate-400">Up to 50 MB</p>
          )}

          <input
            id={inputId}
            ref={inputRef}
            type="file"
            disabled={disabled}
            accept={isImage ? IMAGE_ACCEPT : undefined}
            className="hidden"
            onChange={(event) =>
              validateAndSet(event.target.files?.[0] ?? null)
            }
          />
        </div>
      ) : (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm dark:border-slate-700 dark:bg-slate-800/50">
          <div className="flex min-w-0 items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-green-600" />
            <div className="min-w-0">
              <p className="truncate font-medium text-slate-800 dark:text-slate-200">
                {file.name}
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {file.type || "unknown type"} · {formatBytes(file.size)} · Valid
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={handleRemove}
            disabled={disabled}
            aria-label="Remove selected file"
            className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-200 hover:text-slate-600 dark:hover:bg-slate-700"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {clientError && (
        <p role="alert" className="mt-1.5 text-xs text-red-600 dark:text-red-400">
          {clientError}
        </p>
      )}

      {isImage && (
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
          The image will be analyzed for fingerprints, metadata, and matches
          against previously investigated images.
        </p>
      )}
    </div>
  );
}
