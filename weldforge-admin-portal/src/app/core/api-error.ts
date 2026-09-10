import { HttpErrorResponse } from '@angular/common/http';

/**
 * The human-readable message from a failed API call (CONF-7.3).
 *
 * `/api/**` errors are RFC 9457 problem documents: `detail` is the standard
 * member, and `message` the legacy one the server keeps sending alongside it
 * so older clients do not break. Read the standard field first, so this code
 * keeps working when the legacy member is eventually retired.
 */
export function apiErrorMessage(err: unknown, fallback = ''): string {
  const body = (err as HttpErrorResponse | null | undefined)?.error;
  if (body && typeof body === 'object') {
    const { detail, message } = body as { detail?: unknown; message?: unknown };
    for (const candidate of [detail, message]) {
      if (typeof candidate === 'string' && candidate.trim()) return candidate;
    }
  }
  return fallback;
}
