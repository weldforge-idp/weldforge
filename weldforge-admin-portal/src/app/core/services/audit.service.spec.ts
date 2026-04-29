import { describe, it, expect, beforeEach, vi } from 'vitest';
import '@angular/compiler';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { AuditService, AuditPage, AuditFilter } from './audit.service';

describe('AuditService', () => {
  let http: { post: any; get: any; delete: any; put: any };
  let service: AuditService;

  beforeEach(() => {
    http = { post: vi.fn(), get: vi.fn(), delete: vi.fn(), put: vi.fn() };
    service = new AuditService(http as unknown as HttpClient);
  });

  describe('search', () => {
    it('passes filter params and returns a paged result', () => {
      const page: AuditPage = {
        content: [{ id: 1, eventType: 'LOGIN', outcome: 'SUCCESS', createdAt: '2026-01-01T00:00:00Z' }],
        page: 0, size: 20, totalElements: 1, totalPages: 1,
      };
      http.get.mockReturnValue(of(page));

      const filter: AuditFilter = { eventType: 'LOGIN', page: 0, size: 20 };
      let observed: AuditPage | undefined;
      service.search(filter).subscribe(r => (observed = r));

      expect(http.get).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/audit'),
        expect.objectContaining({ params: expect.anything() })
      );
      // Verify the HttpParams contain the filter values
      const callArgs = http.get.mock.calls[0];
      const params = callArgs[1].params;
      expect(params.get('eventType')).toBe('LOGIN');
      expect(params.get('page')).toBe('0');
      expect(params.get('size')).toBe('20');
      expect(observed).toEqual(page);
    });

    it('omits undefined and empty filter values from params', () => {
      http.get.mockReturnValue(of({ content: [], page: 0, size: 20, totalElements: 0, totalPages: 0 }));

      service.search({ eventType: undefined, actorEmail: '', page: 0 }).subscribe();

      const callArgs = http.get.mock.calls[0];
      const params = callArgs[1].params;
      expect(params.has('eventType')).toBe(false);
      expect(params.has('actorEmail')).toBe(false);
      expect(params.get('page')).toBe('0');
    });
  });

  describe('exportCsvUrl', () => {
    it('builds a URL with query parameters from the filter', () => {
      const url = service.exportCsvUrl({ eventType: 'MFA_ENROLL', since: '2026-01-01' });

      expect(url).toContain('/api/admin/audit/export.csv');
      expect(url).toContain('eventType=MFA_ENROLL');
      expect(url).toContain('since=2026-01-01');
    });

    it('returns a clean URL with no query string when filter is empty', () => {
      const url = service.exportCsvUrl({});

      expect(url).toContain('/api/admin/audit/export.csv');
      expect(url).not.toContain('?');
    });
  });
});
