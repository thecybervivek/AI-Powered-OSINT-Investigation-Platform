import { isAxiosError } from "axios";

/**
 * FastAPI's default error shape puts a human-readable message on
 * `detail` (a string for HTTPException, or a list of pydantic
 * validation-error objects for 422s). This never exposes that raw
 * Axios/response object to the UI - it always returns a short,
 * analyst-friendly sentence, while the original error is still
 * available to log to the console for debugging.
 */
export function getApiErrorMessage(
  error: unknown,
  fallback = "Something went wrong. Please try again."
): string {
  if (!isAxiosError(error)) {
    if (error instanceof Error && error.message) {
      return error.message;
    }

    return fallback;
  }

  if (!error.response) {
    return "Unable to reach the server. Check your connection and try again.";
  }

  const { status, data } = error.response;

  if (status === 401) {
    return "Your session has expired. Please sign in again.";
  }

  if (status === 403) {
    return "You don't have permission to do that.";
  }

  if (status === 404) {
    return "That investigation could not be found.";
  }

  if (status === 429) {
    return "Too many requests. Please wait a moment and try again.";
  }

  if (status >= 500) {
    return "The server ran into a problem processing this investigation. Please try again shortly.";
  }

  const detail = (data as { detail?: unknown } | undefined)?.detail;

  if (typeof detail === "string" && detail.trim()) {
    return detail;
  }

  // 422 pydantic validation errors: a list of { loc, msg, type }.
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as { msg?: string } | undefined;

    if (first?.msg) {
      return first.msg;
    }
  }

  return fallback;
}
