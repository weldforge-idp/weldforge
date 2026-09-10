import { describe, it, expect } from 'vitest';
import { HttpErrorResponse } from '@angular/common/http';
import { apiErrorMessage } from './api-error';

describe('apiErrorMessage', () => {
  const problem = (body: unknown) => new HttpErrorResponse({ status: 400, error: body });

  it('prefers the RFC 9457 detail member', () => {
    expect(apiErrorMessage(problem({ detail: 'from detail', message: 'from message' })))
      .toBe('from detail');
  });

  it('falls back to the legacy message member', () => {
    expect(apiErrorMessage(problem({ error: 'bad_request', message: 'legacy only' })))
      .toBe('legacy only');
  });

  it('uses the fallback when the body carries neither', () => {
    expect(apiErrorMessage(problem('<html>proxy error</html>'), 'Try again')).toBe('Try again');
    expect(apiErrorMessage(problem({ detail: '   ' }), 'Try again')).toBe('Try again');
    expect(apiErrorMessage(undefined, 'Try again')).toBe('Try again');
  });

  it('returns an empty string with no fallback', () => {
    expect(apiErrorMessage(problem({}))).toBe('');
  });
});
