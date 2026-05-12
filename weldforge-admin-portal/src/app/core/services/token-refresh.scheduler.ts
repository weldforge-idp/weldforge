import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { environment } from '../../../environments/environment';

/**
 * Proactively rotates the access JWT just before it expires.
 *
 * Background — the access token has a short server-side TTL (5 minutes
 * on the default tenant). Without this scheduler, every API call after
 * the 5-minute mark would 401 once, the interceptor would refresh on
 * 401, replay the call, and the request would complete with one extra
 * round-trip. With the scheduler, the SPA refreshes BEFORE the token
 * lapses, so the 401 path is only hit on edge cases (server clock drift,
 * paused tab waking up after expiry, refresh failure).
 *
 * Multi-tab — refresh tokens rotate with reuse detection
 * (RefreshTokenService.rotate kills the whole family on a second use of
 * an already-rotated token). If tab A and tab B both fire /refresh with
 * the same cookie value, the second one is interpreted as token theft
 * and logs the user out everywhere. To avoid this, only one tab in a
 * given browser owns the refresh — the other tabs listen on a
 * BroadcastChannel and adopt whatever token the leader produces. The
 * leader is whichever tab is currently focused, or whichever was last
 * to write its own claim to localStorage if no tab is focused. The
 * scheme is best-effort: brief overlap windows are still possible (two
 * tabs opened in the same second), and the reactive interceptor still
 * catches the 401 if the worst happens.
 *
 * The scheduler is a singleton; multiple constructor calls in the same
 * tab share the same setTimeout / BroadcastChannel.
 */
@Injectable({ providedIn: 'root' })
export class TokenRefreshScheduler {
  private readonly http = inject(HttpClient);

  /** Refresh this many seconds BEFORE the JWT's exp. */
  private static readonly LEEWAY_SECONDS = 30;
  /** Floor on the scheduled delay so we don't busy-loop on tiny windows. */
  private static readonly MIN_DELAY_MS = 1_000;

  private static readonly TAB_ID = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  private static readonly LEADER_KEY = 'wf_refresh_leader';
  private static readonly LEADER_TTL_MS = 10_000;
  private static readonly CHANNEL_NAME = 'wf_refresh';

  private timer: ReturnType<typeof setTimeout> | null = null;
  private channel: BroadcastChannel | null = null;
  private channelHandler: ((ev: MessageEvent<unknown>) => void) | null = null;
  private storageHandler: ((ev: StorageEvent) => void) | null = null;

  /**
   * Call on app boot (with the token already in localStorage), after a
   * fresh login/register/MFA-verify, and after the reactive interceptor
   * rotates the token on a 401. Cancels any existing timer and schedules
   * a new one for `exp - LEEWAY_SECONDS`. If the token is already past
   * that point, refreshes immediately.
   */
  scheduleFromToken(token: string | null | undefined): void {
    this.ensureChannel();
    this.cancel();
    if (!token) return;

    const exp = parseExp(token);
    if (exp == null) return;

    const delayMs = Math.max(
      TokenRefreshScheduler.MIN_DELAY_MS,
      exp * 1000 - Date.now() - TokenRefreshScheduler.LEEWAY_SECONDS * 1000,
    );

    this.timer = setTimeout(() => {
      this.timer = null;
      this.refreshIfLeader();
    }, delayMs);
  }

  /** Cancel the pending timer (used by logout). Safe to call repeatedly. */
  cancel(): void {
    if (this.timer != null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  /**
   * Coordinate with other tabs. If we hold the leader claim (or can
   * acquire one), POST /api/auth/refresh and broadcast the new token
   * to followers. Otherwise wait passively — a follower's localStorage
   * `storage` event will pick up the leader's new token and reschedule.
   */
  private async refreshIfLeader(): Promise<void> {
    if (!this.claimLeader()) {
      // Some other tab is the leader; it will broadcast the new token.
      // If no broadcast arrives within a couple of seconds (leader
      // crashed, closed, throttled), the scheduler will fall through
      // to the reactive 401-refresh on the next API call.
      return;
    }

    try {
      const res = await firstValueFrom(
        this.http.post<{ token: string; expiresIn: number }>(
          `${environment.apiBaseUrl}/api/auth/refresh`,
          null,
          { withCredentials: true },
        ),
      );
      localStorage.setItem('access_token', res.token);
      this.broadcastNewToken(res.token);
      this.scheduleFromToken(res.token);
    } catch {
      // Don't blow up. Next /api/** call will 401 and the reactive
      // interceptor handles the failure mode (redirect to /login if the
      // refresh family was revoked or the cookie has truly lapsed).
    } finally {
      this.releaseLeader();
    }
  }

  // ---- Leader election (localStorage-based, best-effort) -----------
  private claimLeader(): boolean {
    const now = Date.now();
    const raw = localStorage.getItem(TokenRefreshScheduler.LEADER_KEY);
    if (raw) {
      try {
        const { tab, until } = JSON.parse(raw) as { tab: string; until: number };
        if (tab !== TokenRefreshScheduler.TAB_ID && until > now) {
          return false;
        }
      } catch {
        // Corrupt claim — treat as no claim.
      }
    }
    localStorage.setItem(
      TokenRefreshScheduler.LEADER_KEY,
      JSON.stringify({
        tab: TokenRefreshScheduler.TAB_ID,
        until: now + TokenRefreshScheduler.LEADER_TTL_MS,
      }),
    );
    return true;
  }

  private releaseLeader(): void {
    const raw = localStorage.getItem(TokenRefreshScheduler.LEADER_KEY);
    if (!raw) return;
    try {
      const { tab } = JSON.parse(raw) as { tab: string };
      if (tab === TokenRefreshScheduler.TAB_ID) {
        localStorage.removeItem(TokenRefreshScheduler.LEADER_KEY);
      }
    } catch {
      // Corrupt — leave alone; the TTL handles it.
    }
  }

  // ---- Cross-tab broadcast -----------------------------------------
  private ensureChannel(): void {
    if (this.channel || typeof BroadcastChannel === 'undefined') {
      this.installStorageFallback();
      return;
    }
    this.channel = new BroadcastChannel(TokenRefreshScheduler.CHANNEL_NAME);
    this.channelHandler = (ev) => this.onMessage(ev.data);
    this.channel.addEventListener('message', this.channelHandler);
    this.installStorageFallback();
  }

  /**
   * Safari and a few embedded browsers still ship without
   * BroadcastChannel. Storage events on the access_token key give us
   * the same notification (followers see the leader's setItem) and we
   * piggy-back on that.
   */
  private installStorageFallback(): void {
    if (this.storageHandler) return;
    this.storageHandler = (ev) => {
      if (ev.key === 'access_token' && ev.newValue) {
        this.scheduleFromToken(ev.newValue);
      }
    };
    window.addEventListener('storage', this.storageHandler);
  }

  private broadcastNewToken(token: string): void {
    this.channel?.postMessage({ kind: 'token', token, from: TokenRefreshScheduler.TAB_ID });
  }

  private onMessage(data: unknown): void {
    if (!data || typeof data !== 'object') return;
    const msg = data as { kind?: string; token?: string; from?: string };
    if (msg.kind === 'token' && msg.token && msg.from !== TokenRefreshScheduler.TAB_ID) {
      // Leader announced a new token; pick it up and reschedule.
      localStorage.setItem('access_token', msg.token);
      this.scheduleFromToken(msg.token);
    }
  }
}

/** Decode `exp` (unix seconds) from a JWT payload, or null if unparseable. */
function parseExp(token: string): number | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(json) as { exp?: number };
    return typeof claims.exp === 'number' ? claims.exp : null;
  } catch {
    return null;
  }
}
