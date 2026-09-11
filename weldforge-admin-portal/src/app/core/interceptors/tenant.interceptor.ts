import { HttpErrorResponse, HttpInterceptorFn, HttpResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { map } from 'rxjs';
import { TenantPickerService } from '../services/tenant-picker.service';
import { AuthService } from '../services/auth.service';
import { slugFromHost } from '../services/public-host';
import { ACTING_TENANT_HEADER, TARGET_TENANT, TENANT_SELECTOR_HEADER } from '../tenant-selector';

const TENANT_HEADER = 'X-Tenant-Slug';

/**
 * Tells the backend which tenant a request is for -- two different questions,
 * two different headers.
 *
 * **Admin calls (`/api/admin/**`)** carry `X-WF-Tenant`: the tenant this call
 * acts in. Source, in order:
 *  1. the request's own {@link TARGET_TENANT} (row-scoped screens set it --
 *     the tenant you are looking at is the tenant you are editing);
 *  2. the super-admin picker ({@link TenantPickerService.outgoingSlug}).
 * With neither, no selector is sent and the call acts in the JWT's home
 * tenant. The backend answers `X-WF-Acting-Tenant`; a response for any other
 * tenant than the one expected is turned into an error, so a misdirected call
 * can never render as a success.
 *
 * **Everything else under `/api/`** carries `X-Tenant-Slug` from the page's
 * host ({slug}.sso.weldforge.org) -- the tenant a sign-in, sign-up or reset is
 * for. The picker is NOT consulted here: acting-as is an admin concept.
 *
 * Until 2026-09-11 the picker stamped `X-Tenant-Slug` on every call and the
 * backend switched tenant on it through a second, unaudited channel; a write
 * that lost the header landed in the home tenant with no error.
 */
export const tenantInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.includes('/api/')) return next(req);

  if (req.url.includes('/api/admin/')) {
    const target = req.context.get(TARGET_TENANT) ?? pickerSlug();
    const outbound = target ? req.clone({ setHeaders: { [TENANT_SELECTOR_HEADER]: target } }) : req;
    const expected = target ?? homeSlug();
    return next(outbound).pipe(map(event => {
      if (event instanceof HttpResponse) {
        const acting = event.headers.get(ACTING_TENANT_HEADER);
        if (acting && expected && acting.toLowerCase() !== expected.toLowerCase()) {
          throw misdirected(req.url, acting, expected);
        }
      }
      return event;
    }));
  }

  if (req.headers.has(TENANT_HEADER)) return next(req);
  const slug = hostSlug();
  return slug ? next(req.clone({ setHeaders: { [TENANT_HEADER]: slug } })) : next(req);
};

/** Shaped like an RFC 9457 problem so the usual error display shows it. */
function misdirected(url: string, acting: string, expected: string): HttpErrorResponse {
  const detail = `This request ran in tenant '${acting}', not '${expected}'. `
    + 'Nothing on this page has been updated; reload and check both tenants before retrying.';
  return new HttpErrorResponse({
    url,
    status: 409,
    statusText: 'Tenant mismatch',
    error: { type: 'tag:weldforge.org,2026:problem:tenant_mismatch', title: 'Tenant mismatch',
             status: 409, detail, error: 'tenant_mismatch', message: detail },
  });
}

function pickerSlug(): string | null {
  try {
    return inject(TenantPickerService).outgoingSlug();
  } catch {
    // inject() throws outside an injection context (very early bootstrap).
    return null;
  }
}

function homeSlug(): string | null {
  try {
    return inject(AuthService).getHomeTenantSlug();
  } catch {
    return null;
  }
}

function hostSlug(): string | null {
  if (typeof window === 'undefined' || !window.location) return null;
  return slugFromHost(window.location.host);
}
