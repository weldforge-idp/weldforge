import { Component, OnInit, signal, inject } from '@angular/core';
import { injectQueryClient } from '@tanstack/angular-query-experimental';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleChange, MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatChipsModule } from '@angular/material/chips';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import {
  SamlBinding,
  SamlProvider,
  SocialProvider,
  SocialProviderType,
  SUPPORTED_PROVIDERS,
  Tenant,
  TenantService,
  PasswordPolicyOverride,
  ResolvedPasswordPolicy
} from '../../core/services/tenant.service';
import { OidcClient, OidcClientService } from '../../core/services/oidc-client.service';
import {
  AUTHN_CONTEXT_PASSWORD_PROTECTED,
  SamlIdpServiceProvider,
  SamlIdpService
} from '../../core/services/saml-idp.service';
import { TenantTwilioService, TwilioProvider } from '../../core/services/tenant-twilio.service';
import { TenantMfaPolicyService, MfaPolicy, MfaEnforcement } from '../../core/services/tenant-mfa-policy.service';
import { environment } from '../../../environments/environment';
import { originsFor, needsWebOrigin } from '../../core/oidc-origins';
import { apiErrorMessage } from '../../core/api-error';

interface BrandingDraft {
  registrationEnabled: boolean;
  passwordRecoveryEnabled: boolean;
  emailVerificationRequired: boolean;
  returnToCallerEnabled: boolean;
  brand: Record<string, string>;
}

/**
 * Editable password-policy override. Blank/null means "inherit", which is why
 * every field is nullable rather than defaulted — a 0 or false would be an
 * override that says something, and an empty box must say nothing.
 */
interface PasswordPolicyDraft {
  minLength: number | null;
  maxLength: number | null;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
}

/** The session / contact / claims fields, as the form edits them. */
interface SessionDraft {
  accessTtlMs: number | null;
  refreshTtlMs: number | null;
  contactEmail: string;
  allowedEmailDomains: string;
  /** JSON TEXT while editing; parsed to an object on save. */
  customClaims: string;
}

interface TenantRow extends Tenant {
  providers?: SocialProvider[];
  samlProviders?: SamlProvider[];
  loadingProviders?: boolean;
  expanded?: boolean;
  draft?: SocialProvider;
  samlDraft?: SamlProvider;
  twilio?: TwilioProvider | null;
  twilioDraft?: TwilioProvider;
  mfaPolicy?: MfaPolicy;
  brandingDraft?: BrandingDraft;
  sessionDraft?: SessionDraft;
  passwordDraft?: PasswordPolicyDraft;
  /** Server-resolved rules for this tenant; refreshed after every save. */
  effectivePassword?: ResolvedPasswordPolicy;
}

@Component({
  selector: 'app-tenants',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatCardModule, MatTableModule, MatButtonModule, MatIconModule,
    MatFormFieldModule, MatInputModule, MatSelectModule, MatSlideToggleModule,
    MatExpansionModule, MatChipsModule, MatSnackBarModule,
  ],
  template: `
    <div class="wf-page">
      <header class="wf-page-header">
        <div>
          <div class="eyebrow mono">// tenants</div>
          <h1>Tenants</h1>
          <p class="sub">Isolated identity domains. Each tenant has its own users, roles, and social login configuration.</p>
        </div>
        <button mat-raised-button color="accent" (click)="startCreate()">
          <mat-icon>add</mat-icon> New Tenant
        </button>
      </header>

      <mat-card *ngIf="creating()" class="wf-card wf-create-card">
        <h3>Create tenant</h3>
        <div class="wf-grid">
          <mat-form-field appearance="outline">
            <mat-label>Slug</mat-label>
            <input matInput [(ngModel)]="newTenant.slug" placeholder="acme" required>
          </mat-form-field>
          <mat-form-field appearance="outline">
            <mat-label>Name</mat-label>
            <input matInput [(ngModel)]="newTenant.name" required>
          </mat-form-field>
          <mat-form-field appearance="outline">
            <mat-label>Display name</mat-label>
            <input matInput [(ngModel)]="newTenant.displayName">
          </mat-form-field>
        </div>
        <div class="wf-actions">
          <button mat-button (click)="cancelCreate()">Cancel</button>
          <button mat-raised-button color="primary" (click)="saveCreate()">Create</button>
        </div>
      </mat-card>

      <mat-accordion multi>
        @for (t of tenants(); track t.id) {
        <mat-expansion-panel (opened)="loadProviders(t)" class="wf-panel">
          <mat-expansion-panel-header>
            <mat-panel-title>
              <span class="slug mono">{{ t.slug }}</span>
              <span class="name">{{ t.displayName || t.name }}</span>
            </mat-panel-title>
            <mat-panel-description>
              <span class="status" [class.on]="t.enabled">{{ t.enabled ? 'enabled' : 'disabled' }}</span>
              @if (t.providers?.length) {
                <span class="chips">
                  @for (p of t.providers; track p.registrationId) {
                    <mat-chip [class.off]="!p.enabled">{{ p.provider }}</mat-chip>
                  }
                </span>
              }
            </mat-panel-description>
          </mat-expansion-panel-header>

          <div class="wf-panel-body">
            <section class="wf-section">
              <h4>Social login providers</h4>
              <p class="sub">Configure which social IdPs this tenant can authenticate against. Each provider is identified in OAuth2 flows as <code>{{ t.slug }}-&lt;provider&gt;</code>.</p>

              <table *ngIf="t.providers && t.providers.length" class="wf-table">
                <thead>
                  <tr><th>Provider</th><th>Client ID</th><th>Scopes</th><th>Status</th><th>Registration ID</th><th></th></tr>
                </thead>
                <tbody>
                  <tr *ngFor="let p of t.providers">
                    <td>{{ p.provider }}</td>
                    <td class="mono trunc">{{ p.clientId }}</td>
                    <td class="mono">{{ p.scopes || '—' }}</td>
                    <td>
                      <mat-slide-toggle [checked]="p.enabled"
                                        (change)="toggleProvider(t, p, $event.checked)">
                      </mat-slide-toggle>
                    </td>
                    <td class="mono">{{ p.registrationId }}</td>
                    <td>
                      <button mat-icon-button color="warn" (click)="removeProvider(t, p)">
                        <mat-icon>delete</mat-icon>
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>

              <div *ngIf="t.providers && !t.providers.length" class="empty mono">
                // no providers configured yet
              </div>

              <div class="wf-add-provider">
                <h5>Add or update provider</h5>
                <div class="wf-grid">
                  <mat-form-field appearance="outline">
                    <mat-label>Provider</mat-label>
                    <mat-select [(ngModel)]="t.draft!.provider">
                      <mat-option *ngFor="let opt of providerTypes" [value]="opt">{{ opt }}</mat-option>
                    </mat-select>
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Client ID</mat-label>
                    <input matInput [(ngModel)]="t.draft!.clientId">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Client Secret</mat-label>
                    <input matInput type="password" [(ngModel)]="t.draft!.clientSecret"
                           placeholder="leave blank to keep existing">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Scopes (override)</mat-label>
                    <input matInput [(ngModel)]="t.draft!.scopes" placeholder="openid profile email">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Button label</mat-label>
                    <input matInput [(ngModel)]="t.draft!.displayName">
                  </mat-form-field>
                </div>
                <div class="wf-actions">
                  <mat-slide-toggle [(ngModel)]="t.draft!.enabled">Enabled</mat-slide-toggle>
                  <span class="spacer"></span>
                  <button mat-raised-button color="primary" (click)="saveProvider(t)">Save Provider</button>
                </div>
              </div>
            </section>

            <!-- ==================== SAML providers ==================== -->
            <section class="wf-section">
              <h4>SAML 2.0 upstream identity providers</h4>
              <p class="sub">Federate users from enterprise SAML IdPs (Okta, Entra ID, ADFS, Keycloak). Each registration is identified as <code>{{ t.slug }}-saml-&lt;providerKey&gt;</code>.</p>

              <table *ngIf="t.samlProviders && t.samlProviders.length" class="wf-table">
                <thead>
                  <tr><th>Key</th><th>Display</th><th>IdP entity</th><th>Status</th><th>SP metadata</th><th></th></tr>
                </thead>
                <tbody>
                  <tr *ngFor="let p of t.samlProviders">
                    <td class="mono">{{ p.providerKey }}</td>
                    <td>{{ p.displayName || '—' }}</td>
                    <td class="mono trunc">{{ p.idpEntityId }}</td>
                    <td>
                      <mat-slide-toggle [checked]="p.enabled" (change)="toggleSamlProvider(t, p, $event.checked)">
                      </mat-slide-toggle>
                    </td>
                    <td>
                      <button mat-icon-button (click)="copy(p.spMetadataUrl!)" title="Copy SP metadata URL">
                        <mat-icon>content_copy</mat-icon>
                      </button>
                    </td>
                    <td>
                      <button mat-icon-button color="warn" (click)="removeSamlProvider(t, p)">
                        <mat-icon>delete</mat-icon>
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>

              <div *ngIf="t.samlProviders && !t.samlProviders.length" class="empty mono">
                // no SAML providers configured yet
              </div>

              <div class="wf-add-provider">
                <h5>Add or update SAML provider</h5>
                <div class="wf-grid">
                  <mat-form-field appearance="outline">
                    <mat-label>Provider key</mat-label>
                    <input matInput [(ngModel)]="t.samlDraft!.providerKey" placeholder="okta">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Display name</mat-label>
                    <input matInput [(ngModel)]="t.samlDraft!.displayName" placeholder="Login with Okta">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>IdP entity ID</mat-label>
                    <input matInput [(ngModel)]="t.samlDraft!.idpEntityId">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>IdP SSO URL</mat-label>
                    <input matInput [(ngModel)]="t.samlDraft!.idpSsoUrl">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>IdP SLO URL</mat-label>
                    <input matInput [(ngModel)]="t.samlDraft!.idpSloUrl">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>SSO binding</mat-label>
                    <mat-select [(ngModel)]="t.samlDraft!.ssoBinding">
                      <mat-option value="POST">POST</mat-option>
                      <mat-option value="REDIRECT">REDIRECT</mat-option>
                    </mat-select>
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Email attribute</mat-label>
                    <input matInput [(ngModel)]="t.samlDraft!.emailAttribute" placeholder="email">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Name attribute</mat-label>
                    <input matInput [(ngModel)]="t.samlDraft!.nameAttribute" placeholder="name">
                  </mat-form-field>
                </div>
                <mat-form-field appearance="outline" class="wf-cert-field">
                  <mat-label>IdP signing certificate (PEM)</mat-label>
                  <textarea matInput rows="5" [(ngModel)]="t.samlDraft!.idpSigningCertificate"
                            placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----&#10;Leave blank to keep existing"></textarea>
                </mat-form-field>
                <div class="wf-actions">
                  <mat-slide-toggle [(ngModel)]="t.samlDraft!.wantAssertionsSigned">Require signed assertions</mat-slide-toggle>
                  <mat-slide-toggle [(ngModel)]="t.samlDraft!.enabled">Enabled</mat-slide-toggle>
                  <span class="spacer"></span>
                  <button mat-raised-button color="primary" (click)="saveSamlProvider(t)">Save SAML Provider</button>
                </div>
              </div>
            </section>

            <!-- ==================== Twilio (SMS MFA) ==================== -->
            <section class="wf-section">
              <h4>Twilio — SMS MFA provider</h4>
              <p class="sub">Per-tenant Twilio credentials used for SMS OTP second-factor authentication. Each tenant uses its own Twilio subaccount and caller-id. The auth token is AES-GCM encrypted at rest and never returned via the API.</p>

              <div *ngIf="t.twilio" class="wf-twilio-status">
                <div>
                  <strong>Account SID:</strong> <code class="mono">{{ t.twilio.accountSid }}</code>
                </div>
                <div>
                  <strong>From:</strong> <code class="mono">{{ t.twilio.fromPhone }}</code>
                </div>
                <div *ngIf="t.twilio.messagingServiceSid">
                  <strong>Messaging Service:</strong> <code class="mono">{{ t.twilio.messagingServiceSid }}</code>
                </div>
                <div>
                  <strong>Status:</strong>
                  <mat-slide-toggle [checked]="!!t.twilio.enabled"
                                    (change)="toggleTwilio(t, $event.checked)">
                    {{ t.twilio.enabled ? 'enabled' : 'disabled' }}
                  </mat-slide-toggle>
                </div>
                <div>
                  <strong>Auth token:</strong>
                  <span *ngIf="t.twilio.authTokenSet" class="mono">(set)</span>
                  <span *ngIf="!t.twilio.authTokenSet" class="mono">(missing)</span>
                </div>
              </div>

              <div *ngIf="!t.twilio" class="empty mono">
                // no Twilio configured yet
              </div>

              <div class="wf-add-provider">
                <h5>{{ t.twilio ? 'Update Twilio config' : 'Configure Twilio' }}</h5>
                <div class="wf-grid">
                  <mat-form-field appearance="outline">
                    <mat-label>Account SID</mat-label>
                    <input matInput [(ngModel)]="t.twilioDraft!.accountSid" placeholder="ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Auth Token</mat-label>
                    <input matInput type="password" [(ngModel)]="t.twilioDraft!.authToken"
                           placeholder="leave blank to keep existing">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>From phone (E.164)</mat-label>
                    <input matInput [(ngModel)]="t.twilioDraft!.fromPhone" placeholder="+27821234567">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Messaging Service SID (optional)</mat-label>
                    <input matInput [(ngModel)]="t.twilioDraft!.messagingServiceSid" placeholder="MGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">
                  </mat-form-field>
                </div>
                <div class="wf-actions">
                  <mat-slide-toggle [(ngModel)]="t.twilioDraft!.enabled">Enabled</mat-slide-toggle>
                  <span class="spacer"></span>
                  <button *ngIf="t.twilio" mat-stroked-button color="warn" (click)="deleteTwilio(t)">
                    <mat-icon>delete</mat-icon> Remove
                  </button>
                  <button mat-raised-button color="primary" (click)="saveTwilio(t)">
                    {{ t.twilio ? 'Update' : 'Save' }}
                  </button>
                </div>
              </div>
            </section>

            <!-- ==================== MFA enforcement policy ==================== -->
            <section class="wf-section">
              <h4>MFA enforcement policy</h4>
              <p class="sub">Control whether users must enroll a second factor. <strong>REQUIRED</strong> blocks login for users with no verified factor after the grace period expires. Step-up age forces re-authentication on high-assurance OIDC clients even within an active SSO session.</p>

              <div *ngIf="t.mfaPolicy" class="wf-add-provider">
                <div class="wf-grid">
                  <mat-form-field appearance="outline">
                    <mat-label>Enforcement</mat-label>
                    <mat-select [(ngModel)]="t.mfaPolicy!.enforcement">
                      <mat-option value="OPTIONAL">Optional — users may enroll</mat-option>
                      <mat-option value="REQUIRED">Required — block login without a factor</mat-option>
                      <mat-option value="RISK_ADAPTIVE">Risk-adaptive (reserved)</mat-option>
                    </mat-select>
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Grace period (days)</mat-label>
                    <input matInput type="number" min="0" [(ngModel)]="t.mfaPolicy!.gracePeriodDays">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Default step-up age (seconds)</mat-label>
                    <input matInput type="number" min="0" [(ngModel)]="t.mfaPolicy!.defaultStepupMaxAge">
                  </mat-form-field>
                </div>
                <div class="wf-actions">
                  <span class="spacer"></span>
                  <button mat-raised-button color="primary" (click)="saveMfaPolicy(t)">Save Policy</button>
                </div>
              </div>
            </section>

            <!-- ==================== OIDC clients ==================== -->
            <section class="wf-section">
              <h4>OIDC relying parties <span class="mono tenant-tag">{{ t.slug }}</span></h4>
              <p class="sub">Apps that authenticate <em>via</em> WeldForge as their OpenID Connect identity provider. Each client gets its own secret and may register multiple redirect URIs. Everything here is read from and written to <code>{{ t.slug }}</code>, whatever the "Acting as tenant" picker says.</p>

              <!-- Issued credentials. A browser alert was the wrong place for a
                   secret: it cannot be selected reliably, it is dismissed by a
                   stray Enter, and it blocks the page. This panel stays until
                   it is dismissed, and offers the copy the operator actually
                   needs. -->
              <div *ngIf="issuedFor(t) as issued" class="wf-secret-panel">
                <div class="wf-secret-head">
                  <h5>{{ issued.secret ? 'Client secret — shown once' : 'Public client created' }}</h5>
                  <button mat-icon-button (click)="dismissIssued()" aria-label="Dismiss" title="Dismiss">
                    <mat-icon>close</mat-icon>
                  </button>
                </div>
                <p class="sub">{{ issued.note }}</p>
                <div class="wf-secret-row">
                  <span class="wf-secret-label">client_id</span>
                  <code class="mono wf-secret-value">{{ issued.clientId }}</code>
                  <button mat-stroked-button (click)="copy(issued.clientId)">Copy</button>
                </div>
                <div class="wf-secret-row" *ngIf="issued.secret">
                  <span class="wf-secret-label">client_secret</span>
                  <code class="mono wf-secret-value">{{ secretVisible() ? issued.secret : '•••••••••••••••••••••••••••••••' }}</code>
                  <button mat-icon-button (click)="secretVisible.set(!secretVisible())"
                          [attr.aria-label]="secretVisible() ? 'Hide secret' : 'Show secret'"
                          [attr.aria-pressed]="secretVisible()"
                          [title]="secretVisible() ? 'Hide secret' : 'Show secret'">
                    <mat-icon>{{ secretVisible() ? 'visibility_off' : 'visibility' }}</mat-icon>
                  </button>
                  <button mat-flat-button color="primary" (click)="copy(issued.secret!)">Copy secret</button>
                </div>
              </div>

              <table *ngIf="oidcClientsFor(t).length" class="wf-table">
                <thead>
                  <tr><th>client_id</th><th>Name</th><th>Type</th><th>Redirect URIs</th><th>Scopes</th><th>Grants</th><th>PKCE</th><th></th></tr>
                </thead>
                <tbody>
                  <ng-container *ngFor="let c of oidcClientsFor(t)">
                  <tr>
                    <td class="mono trunc">{{ c.clientId }}</td>
                    <td>{{ c.name || '—' }}</td>
                    <td>{{ c.publicClient ? 'public' : 'confidential' }}</td>
                    <td class="mono trunc">{{ (c.redirectUris || []).join(', ') }}</td>
                    <td class="mono">{{ (c.scopes || []).join(' ') }}</td>
                    <td class="mono">{{ (c.grantTypes || []).join(' ') }}</td>
                    <td>{{ c.requirePkce ? 'yes' : 'no' }}</td>
                    <td>
                      <button mat-icon-button (click)="startEditOidc(c)" title="Edit configuration">
                        <mat-icon>edit</mat-icon>
                      </button>
                      <button mat-icon-button *ngIf="!c.publicClient" (click)="rotateOidcSecret(t, c)" title="Rotate secret">
                        <mat-icon>refresh</mat-icon>
                      </button>
                      <button mat-icon-button color="warn" (click)="removeOidcClient(t, c)">
                        <mat-icon>delete</mat-icon>
                      </button>
                    </td>
                  </tr>
                  <!-- Editing what a client already has, rather than deleting and
                       recreating it. Recreating mints a new secret and drops the
                       refresh-token families bound to the old row, so every
                       signed-in user is logged out. -->
                  <tr *ngIf="editOidcId === c.id">
                    <td colspan="8">
                      <div class="wf-grid">
                        <mat-form-field appearance="outline">
                          <mat-label>Redirect URIs (space-separated)</mat-label>
                          <input matInput [(ngModel)]="editOidc.redirects">
                        </mat-form-field>
                        <mat-form-field appearance="outline" subscriptSizing="dynamic">
                          <mat-label>Web origins (space-separated)</mat-label>
                          <input matInput [(ngModel)]="editOidc.webOrigins">
                          <mat-hint *ngIf="c.publicClient">Required for a browser client; clearing it blocks every call with CORS.</mat-hint>
                        </mat-form-field>
                        <mat-form-field appearance="outline">
                          <mat-label>Post-logout redirect URIs (space-separated)</mat-label>
                          <input matInput [(ngModel)]="editOidc.postLogout">
                        </mat-form-field>
                        <mat-form-field appearance="outline">
                          <mat-label>Scopes</mat-label>
                          <input matInput [(ngModel)]="editOidc.scopes">
                        </mat-form-field>
                        <mat-form-field appearance="outline">
                          <mat-label>Grant types</mat-label>
                          <input matInput [(ngModel)]="editOidc.grants">
                        </mat-form-field>
                        <mat-form-field appearance="outline" class="wide" subscriptSizing="dynamic">
                          <mat-label>Login-screen branding (JSON object)</mat-label>
                          <textarea matInput rows="3" [(ngModel)]="editOidc.branding"
                                    placeholder='blank = use the tenant&apos;s branding'></textarea>
                          <mat-hint [class.wf-error-hint]="!!editOidcBrandingError()">
                            {{ editOidcBrandingError() || 'Overlays the tenant key by key, so set only what differs.' }}
                          </mat-hint>
                        </mat-form-field>
                        <mat-form-field appearance="outline">
                          <mat-label>Refresh token lifetime (seconds)</mat-label>
                          <input matInput type="number" min="1" [(ngModel)]="editOidc.refreshTtl"
                                 placeholder="blank = inherit tenant, then instance">
                        </mat-form-field>
                      </div>
                      <p class="sub">
                        client_id, the secret and public/confidential cannot be changed here —
                        each would break tokens already issued. Create a new client instead.
                      </p>
                      <div class="wf-actions">
                        <button mat-button (click)="cancelEditOidc()">Cancel</button>
                        <span class="spacer"></span>
                        <button mat-raised-button color="primary" (click)="saveEditOidc(t, c)">Save</button>
                      </div>
                    </td>
                  </tr>
                  </ng-container>
                </tbody>
              </table>

              <div *ngIf="!oidcClientsFor(t).length" class="empty mono">
                // no OIDC clients configured for {{ t.slug }} yet
              </div>

              <div class="wf-add-provider">
                <h5>Register a new OIDC client in {{ t.slug }}</h5>
                <div class="wf-grid">
                  <mat-form-field appearance="outline">
                    <mat-label>Client name</mat-label>
                    <input matInput [(ngModel)]="newOidcClient.name" placeholder="Acme dashboard">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>client_id (optional)</mat-label>
                    <input matInput [(ngModel)]="newOidcClientId" placeholder="generated if blank, e.g. keycrypt">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Redirect URIs (space-separated)</mat-label>
                    <input matInput [(ngModel)]="newOidcRedirects" placeholder="https://app.acme.test/callback">
                  </mat-form-field>
                  <mat-form-field appearance="outline" subscriptSizing="dynamic">
                    <mat-label>Web origins (space-separated)</mat-label>
                    <input matInput [(ngModel)]="newOidcWebOrigins"
                           placeholder="https://app.acme.test">
                    <mat-hint>{{ webOriginHint() }}</mat-hint>
                  </mat-form-field>
                  <mat-form-field appearance="outline" subscriptSizing="dynamic">
                    <mat-label>Post-logout redirect URIs (space-separated)</mat-label>
                    <input matInput [(ngModel)]="newOidcPostLogout"
                           placeholder="https://app.acme.test/callback">
                    <mat-hint>Where RP-initiated logout may return. Empty = the client cannot pass one.</mat-hint>
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Scopes</mat-label>
                    <input matInput [(ngModel)]="newOidcScopes" placeholder="openid profile email">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Grant types</mat-label>
                    <input matInput [(ngModel)]="newOidcGrants" placeholder="authorization_code">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Max authentication age (seconds)</mat-label>
                    <input matInput type="number" min="0" [(ngModel)]="newOidcMaxAge" placeholder="0 = tenant default">
                  </mat-form-field>
                  <mat-form-field appearance="outline" subscriptSizing="dynamic">
                    <mat-label>Refresh token lifetime (seconds)</mat-label>
                    <input matInput type="number" min="1" [(ngModel)]="newOidcRefreshTtl"
                           placeholder="blank = inherit tenant, then instance">
                    <mat-hint>{{ refreshTtlHint() }}</mat-hint>
                  </mat-form-field>
                </div>
                <div class="wf-actions">
                  <mat-slide-toggle [(ngModel)]="newOidcPublic"
                                    title="Browser SPAs and native apps: PKCE only, no client secret">Public client</mat-slide-toggle>
                  <mat-slide-toggle [ngModel]="newOidcRequirePkce || newOidcPublic"
                                    (ngModelChange)="newOidcRequirePkce = $event"
                                    [disabled]="newOidcPublic">Require PKCE</mat-slide-toggle>
                  <mat-slide-toggle [(ngModel)]="newOidcRequireMfa">Require MFA</mat-slide-toggle>
                  <span class="spacer"></span>
                  <button mat-raised-button color="primary" (click)="createOidcClient(t)">Create client in {{ t.slug }}</button>
                </div>
              </div>
            </section>

            <!-- ==================== SAML IdP service providers ==================== -->
            <section class="wf-section">
              <h4>SAML IdP — downstream service providers <span class="mono tenant-tag">{{ t.slug }}</span></h4>
              <p class="sub">Apps that receive SAML assertions from WeldForge. Register each SP's entity ID and Assertion Consumer Service URL.</p>

              <div class="wf-toggle-row">
                <mat-slide-toggle [checked]="!!t.samlWantAuthnRequestsSigned"
                                  (change)="setMetadataWantsSignedRequests(t, $event.checked)">
                  Metadata asks SPs to sign AuthnRequests
                </mat-slide-toggle>
                <p class="sub">Published as <code>WantAuthnRequestsSigned</code>. This states intent only; it does not enforce anything. Turn it on first, let each SP start signing, then enable <em>Signed requests</em> on that SP. Enforcing before the SP signs breaks its login.</p>
              </div>

              <table *ngIf="samlSpsFor(t).length" class="wf-table">
                <thead>
                  <tr><th>Entity ID</th><th>Name</th><th>ACS URL</th><th>Status</th>
                      <th title="Verify this SP's request signatures">Signed requests</th>
                      <th title="Issuer on assertions and logout messages">Issuer</th>
                      <th title="AuthnContextClassRef on assertions">Auth context</th>
                      <th title="Encrypt the assertion to the SP's certificate">Encrypted</th>
                      <th>IdP metadata</th><th></th></tr>
                </thead>
                <tbody>
                  <tr *ngFor="let sp of samlSpsFor(t)">
                    <td class="mono trunc">{{ sp.entityId }}</td>
                    <td>{{ sp.name || '—' }}</td>
                    <td class="mono trunc">{{ sp.acsUrl }}</td>
                    <td>
                      <span class="status" [class.on]="sp.enabled">{{ sp.enabled ? 'enabled' : 'disabled' }}</span>
                    </td>
                    <td>
                      <mat-slide-toggle [checked]="!!sp.wantAuthnRequestSigned"
                                        [disabled]="!sp.spCertificate"
                                        [title]="sp.spCertificate ? 'Reject unsigned or badly signed requests' : 'Upload the SP certificate first'"
                                        (change)="setSpRequiresSignedRequests(t, sp, $event)">
                      </mat-slide-toggle>
                    </td>
                    <td>
                      <mat-slide-toggle [checked]="!!sp.useEntityIdAsIssuer"
                                        [title]="sp.useEntityIdAsIssuer ? 'Sending the metadata entityID' : 'Sending the legacy ' + t.slug + '-idp'"
                                        (change)="setSpEntityIdIssuer(t, sp, $event)">
                        {{ sp.useEntityIdAsIssuer ? 'entityID' : 'legacy' }}
                      </mat-slide-toggle>
                    </td>
                    <td>
                      <mat-slide-toggle [checked]="!sp.authnContextOverride"
                                        [title]="sp.authnContextOverride ? 'Pinned to ' + sp.authnContextOverride : 'Reports how the user actually signed in'"
                                        (change)="setSpContextFromSession(t, sp, $event)">
                        {{ sp.authnContextOverride ? 'pinned' : 'from session' }}
                      </mat-slide-toggle>
                    </td>
                    <td>
                      <mat-slide-toggle [checked]="!!sp.encryptAssertions"
                                        [disabled]="!sp.spCertificate"
                                        [title]="sp.spCertificate ? 'Encrypt assertions to the certificate on file' : 'Upload the SP certificate first'"
                                        (change)="setSpEncryptAssertions(t, sp, $event)">
                      </mat-slide-toggle>
                    </td>
                    <td>
                      <button mat-icon-button (click)="copyIdpMetadataUrl(t)" title="Copy IdP metadata URL">
                        <mat-icon>content_copy</mat-icon>
                      </button>
                    </td>
                    <td>
                      <button mat-icon-button color="warn" (click)="removeSamlIdpSp(t, sp)">
                        <mat-icon>delete</mat-icon>
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>

              <div *ngIf="!samlSpsFor(t).length" class="empty mono">
                // no downstream SAML service providers configured for {{ t.slug }} yet
              </div>

              <div class="wf-add-provider">
                <h5>Register a new SAML service provider in {{ t.slug }}</h5>
                <div class="wf-grid">
                  <mat-form-field appearance="outline">
                    <mat-label>Entity ID</mat-label>
                    <input matInput [(ngModel)]="samlIdpDraft.entityId" placeholder="urn:example:sp">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Name</mat-label>
                    <input matInput [(ngModel)]="samlIdpDraft.name" placeholder="Acme App">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>ACS URL</mat-label>
                    <input matInput [(ngModel)]="samlIdpDraft.acsUrl" placeholder="https://app.acme.test/saml/acs">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>SLO URL</mat-label>
                    <input matInput [(ngModel)]="samlIdpDraft.sloUrl" placeholder="https://app.acme.test/saml/slo">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>NameID format</mat-label>
                    <mat-select [(ngModel)]="samlIdpDraft.nameIdFormat">
                      <mat-option value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">emailAddress</mat-option>
                      <mat-option value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">persistent</mat-option>
                    </mat-select>
                  </mat-form-field>
                </div>
                <mat-form-field appearance="outline" class="wf-cert-field">
                  <mat-label>SP certificate (PEM)</mat-label>
                  <textarea matInput rows="5" [(ngModel)]="samlIdpDraft.spCertificate"
                            placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
                </mat-form-field>
                <div class="wf-actions">
                  <mat-slide-toggle [(ngModel)]="samlIdpDraft.enabled">Enabled</mat-slide-toggle>
                  <span class="spacer"></span>
                  <button mat-raised-button color="primary" (click)="createSamlIdpSp(t)">Register SP in {{ t.slug }}</button>
                </div>
              </div>
            </section>

            <!-- ============ Sessions, contact & extra claims ============ -->
            <!-- Every field here is settable through /api/admin/tenants and
                 had no control at all: session lifetimes, the address that
                 receives identity-proofing challenges, the tenant's
                 verification state, and the claims merged into its tokens. -->
            <section class="wf-section">
              <h4>Sessions, contact &amp; token claims <span class="mono tenant-tag">{{ t.slug }}</span></h4>
              <p class="sub">Token lifetimes for <code>{{ t.slug }}</code>, the address identity-proofing challenges are sent to, and any extra claims merged into every token this tenant issues.</p>

              <div class="wf-grid">
                <mat-form-field appearance="outline" subscriptSizing="dynamic">
                  <mat-label>Access token lifetime (ms)</mat-label>
                  <input matInput type="number" min="0" [(ngModel)]="t.sessionDraft!.accessTtlMs"
                         placeholder="blank = deployment default">
                  <mat-hint>{{ humanMs(t.sessionDraft!.accessTtlMs) }}</mat-hint>
                </mat-form-field>
                <mat-form-field appearance="outline" subscriptSizing="dynamic">
                  <mat-label>Refresh token lifetime (ms)</mat-label>
                  <input matInput type="number" min="0" [(ngModel)]="t.sessionDraft!.refreshTtlMs"
                         placeholder="blank = deployment default">
                  <mat-hint>{{ humanMs(t.sessionDraft!.refreshTtlMs) }}</mat-hint>
                </mat-form-field>
                <mat-form-field appearance="outline" class="wide" subscriptSizing="dynamic">
                  <mat-label>Allowed email domains (space-separated)</mat-label>
                  <input matInput [(ngModel)]="t.sessionDraft!.allowedEmailDomains"
                         placeholder="blank = anyone may sign in">
                  <mat-hint>Who may sign in to this tenant. A subdomain of an allowed domain counts; a lookalike does not.</mat-hint>
                </mat-form-field>
                <mat-form-field appearance="outline" subscriptSizing="dynamic">
                  <mat-label>Contact email</mat-label>
                  <input matInput type="email" [(ngModel)]="t.sessionDraft!.contactEmail"
                         placeholder="owner@example.com">
                  <mat-hint>Where identity-proofing challenges are sent.</mat-hint>
                </mat-form-field>
                <mat-form-field appearance="outline" class="wide" subscriptSizing="dynamic">
                  <mat-label>Custom claims (JSON object)</mat-label>
                  <textarea matInput rows="3" [(ngModel)]="t.sessionDraft!.customClaims"
                            placeholder='&#123;"org": "Acme"&#125;'></textarea>
                  <mat-hint [class.wf-error-hint]="!!customClaimsError(t)">
                    {{ customClaimsError(t) || 'Merged into every token this tenant issues.' }}
                  </mat-hint>
                </mat-form-field>
              </div>

              <p class="sub">
                Identity proofing:
                <strong>{{ t.verifiedAt ? 'verified ' + (t.verifiedAt | date:'yyyy-MM-dd') : 'not verified' }}</strong>.
                Set by the verification flow, not editable here.
              </p>

              <div class="wf-actions">
                <span class="spacer"></span>
                <button mat-raised-button color="primary"
                        [disabled]="!!customClaimsError(t)"
                        (click)="saveSessionSettings(t)">Save for {{ t.slug }}</button>
              </div>
            </section>

            <!-- ==================== Branding & Login ==================== -->
            <section class="wf-section">
              <h4>Branding &amp; login screen</h4>
              <p class="sub">Customize how the login screen looks and which self-service flows are exposed for tenant <code>{{ t.slug }}</code>. End users land here when they navigate to <code>https://{{ t.slug }}.sso.weldforge.org/login</code>.</p>

              <div class="wf-grid">
                <div class="wf-toggle-row">
                  <mat-slide-toggle [(ngModel)]="t.brandingDraft!.registrationEnabled">
                    Self-registration enabled
                  </mat-slide-toggle>
                  <p class="sub">When off, <code>/auth/register</code> returns 404 and the "Create account" link disappears from /login.</p>
                </div>
                <div class="wf-toggle-row">
                  <mat-slide-toggle [(ngModel)]="t.brandingDraft!.passwordRecoveryEnabled">
                    Password recovery enabled
                  </mat-slide-toggle>
                  <p class="sub">When off, <code>/auth/forgot-password</code> returns 404 and the "Forgot password?" link disappears.</p>
                </div>
                <div class="wf-toggle-row">
                  <mat-slide-toggle [(ngModel)]="t.brandingDraft!.emailVerificationRequired">
                    Email verification required
                  </mat-slide-toggle>
                  <p class="sub">When on, new accounts must confirm their email before they can sign in.</p>
                </div>
                <div class="wf-toggle-row">
                  <mat-slide-toggle [(ngModel)]="t.brandingDraft!.returnToCallerEnabled">
                    Return to app after password reset
                  </mat-slide-toggle>
                  <p class="sub">When on, a password reset started from inside an app returns the user to the sign-in screen with the original flow preserved, so they continue straight back to the calling app. When off, the reset ends on a standalone confirmation screen.</p>
                </div>
              </div>

              <div class="wf-grid wf-branding-grid">
                <mat-form-field appearance="outline">
                  <mat-label>Logo URL</mat-label>
                  <input matInput [(ngModel)]="t.brandingDraft!.brand['logoUrl']"
                         placeholder="https://cdn.example.com/logo.svg">
                </mat-form-field>
                <mat-form-field appearance="outline">
                  <mat-label>Headline</mat-label>
                  <input matInput [(ngModel)]="t.brandingDraft!.brand['headline']"
                         [placeholder]="'Sign in to ' + (t.displayName || t.slug)">
                </mat-form-field>
                <mat-form-field appearance="outline">
                  <mat-label>Tagline</mat-label>
                  <input matInput [(ngModel)]="t.brandingDraft!.brand['tagline']"
                         placeholder="Welcome, refreshed.">
                </mat-form-field>
                <mat-form-field appearance="outline">
                  <mat-label>Eyebrow text</mat-label>
                  <input matInput [(ngModel)]="t.brandingDraft!.brand['eyebrow']"
                         placeholder="// secure access">
                </mat-form-field>
                <mat-form-field appearance="outline">
                  <mat-label>CTA button label</mat-label>
                  <input matInput [(ngModel)]="t.brandingDraft!.brand['ctaLabel']"
                         placeholder="Sign in">
                </mat-form-field>
              </div>

              <h5 class="wf-subhead">Colors</h5>
              <div class="wf-grid wf-color-grid">
                <label class="wf-color-field">
                  <span>Primary</span>
                  <input type="color" [(ngModel)]="t.brandingDraft!.brand['primaryColor']">
                  <input matInput class="hex" [(ngModel)]="t.brandingDraft!.brand['primaryColor']" placeholder="#4A8FF5">
                </label>
                <label class="wf-color-field">
                  <span>Primary (dark)</span>
                  <input type="color" [(ngModel)]="t.brandingDraft!.brand['primaryDarkColor']">
                  <input matInput class="hex" [(ngModel)]="t.brandingDraft!.brand['primaryDarkColor']" placeholder="#2D5FA8">
                </label>
                <label class="wf-color-field">
                  <span>Accent</span>
                  <input type="color" [(ngModel)]="t.brandingDraft!.brand['accentColor']">
                  <input matInput class="hex" [(ngModel)]="t.brandingDraft!.brand['accentColor']" placeholder="#E8921F">
                </label>
                <label class="wf-color-field">
                  <span>Background</span>
                  <input type="color" [(ngModel)]="t.brandingDraft!.brand['bgColor']">
                  <input matInput class="hex" [(ngModel)]="t.brandingDraft!.brand['bgColor']" placeholder="#070B17">
                </label>
                <label class="wf-color-field">
                  <span>Card background</span>
                  <input type="color" [(ngModel)]="t.brandingDraft!.brand['bg2Color']">
                  <input matInput class="hex" [(ngModel)]="t.brandingDraft!.brand['bg2Color']" placeholder="#0C1020">
                </label>
                <label class="wf-color-field">
                  <span>Text</span>
                  <input type="color" [(ngModel)]="t.brandingDraft!.brand['textColor']">
                  <input matInput class="hex" [(ngModel)]="t.brandingDraft!.brand['textColor']" placeholder="#EEF2FF">
                </label>
              </div>

              <h5 class="wf-subhead">Typography</h5>
              <div class="wf-grid">
                <mat-form-field appearance="outline">
                  <mat-label>Display font (CSS family)</mat-label>
                  <input matInput [(ngModel)]="t.brandingDraft!.brand['displayFont']"
                         placeholder="'Fraunces', serif">
                </mat-form-field>
                <mat-form-field appearance="outline">
                  <mat-label>Body font (CSS family)</mat-label>
                  <input matInput [(ngModel)]="t.brandingDraft!.brand['sansFont']"
                         placeholder="'Inter', sans-serif">
                </mat-form-field>
              </div>

              <div class="wf-actions">
                <span class="spacer"></span>
                <button mat-stroked-button (click)="resetBrandingDraft(t)">Reset</button>
                <button mat-raised-button color="primary" (click)="saveBranding(t)">Save branding</button>
              </div>
            </section>

            <!-- ==================== Password policy ==================== -->
            <section class="wf-subsection">
              <h4>Password policy</h4>
              <p class="wf-hint">
                Rules for this tenant's users. Leave a field blank to inherit the
                deployment default. A policy can only make the deployment default
                <strong>stricter</strong> — a weaker value is kept but has no
                effect until the default relaxes, which is what the
                <em>In effect</em> column shows.
              </p>

              <div class="wf-grid">
                <mat-form-field appearance="outline" subscriptSizing="dynamic">
                  <mat-label>Minimum length</mat-label>
                  <input matInput type="number" min="1" max="72" placeholder="inherit"
                         [(ngModel)]="t.passwordDraft!.minLength">
                  <mat-hint>{{ lengthHint(t, 'minLength') }}</mat-hint>
                </mat-form-field>
                <mat-form-field appearance="outline" subscriptSizing="dynamic">
                  <mat-label>Maximum length</mat-label>
                  <input matInput type="number" min="1" max="72" placeholder="inherit"
                         [(ngModel)]="t.passwordDraft!.maxLength">
                  <mat-hint>{{ lengthHint(t, 'maxLength') }}</mat-hint>
                </mat-form-field>
              </div>

              <div class="wf-toggle-row">
                @for (rule of compositionRules; track rule.key) {
                  <div>
                    <mat-slide-toggle [(ngModel)]="t.passwordDraft![rule.key]"
                                      [disabled]="baseRequires(rule.key)">
                      Require {{ rule.label }}
                    </mat-slide-toggle>
                    <p class="sub">{{ ruleHint(t, rule.key) }}</p>
                  </div>
                }
              </div>

              <p class="wf-hint">
                Breach screening is set for the whole deployment and cannot be
                changed per tenant.
              </p>

              <div class="wf-actions">
                <span class="spacer"></span>
                <button mat-stroked-button (click)="clearPasswordPolicy(t)"
                        title="Remove this tenant's override and inherit the deployment default">
                  Inherit default
                </button>
                <button mat-stroked-button (click)="resetPasswordDraft(t)">Reset</button>
                <button mat-raised-button color="primary" (click)="savePasswordPolicy(t)">
                  Save policy
                </button>
              </div>
            </section>

            <div class="wf-panel-footer">
              <button mat-stroked-button color="warn" (click)="deleteTenant(t)">
                <mat-icon>delete_forever</mat-icon> Delete Tenant
              </button>
            </div>
          </div>
        </mat-expansion-panel>
        }
      </mat-accordion>
    </div>
  `,
  styles: [`
    :host { display: block; }

    .wf-page { padding: 8px 0 48px; }

    .wf-page-header {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 24px;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--wf-border);
    }
    .wf-page-header h1 {
      font-family: 'Syne', sans-serif;
      font-size: 28px;
      margin: 4px 0 6px;
    }
    .eyebrow {
      font-size: 11px;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: var(--wf-amber);
    }
    .sub { color: var(--wf-text-2); font-size: 13px; margin: 0; }

    /* Names the tenant a row-scoped section acts in. */
    .tenant-tag {
      margin-left: 8px;
      padding: 1px 8px;
      border: 1px solid var(--wf-amber);
      border-radius: 10px;
      color: var(--wf-amber);
      font-size: 11px;
      font-weight: normal;
    }

    .wf-card { padding: 20px; margin-bottom: 20px; }
    .wf-create-card h3 {
      font-family: 'Syne', sans-serif;
      margin: 0 0 16px;
    }

    .wf-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      /* Without this a grid row stretches every cell to the tallest one, so
         a field with a three-line hint drags its neighbours' outlines down
         with it. Each field keeps its own height instead. */
      align-items: start;
    }

    .wf-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 12px;
    }
    .spacer { flex: 1 1 auto; }

    .wf-panel {
      background: var(--wf-bg-2) !important;
      border: 1px solid var(--wf-border);
      margin-bottom: 12px;
    }
    .wf-panel .slug {
      color: var(--wf-amber);
      font-weight: 700;
      padding-right: 14px;
      border-right: 1px solid var(--wf-border-2);
      margin-right: 14px;
    }
    .wf-panel .name {
      color: var(--wf-text);
      font-family: 'Syne', sans-serif;
    }
    .status {
      font-family: 'Space Mono', monospace;
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 2px;
      background: rgba(255, 80, 80, 0.15);
      color: #FF6B6B;
      margin-right: 12px;
    }
    .status.on {
      background: rgba(74, 143, 245, 0.15);
      color: var(--wf-blue);
    }
    .chips { display: inline-flex; gap: 4px; }
    .chips mat-chip { font-size: 10px !important; }
    .chips mat-chip.off { opacity: 0.4; }

    .wf-panel-body { padding: 8px 4px 16px; }
    .wf-section h4 {
      font-family: 'Syne', sans-serif;
      margin: 0 0 6px;
      font-size: 16px;
    }
    .wf-section h5 {
      font-family: 'Syne', sans-serif;
      margin: 18px 0 8px;
      font-size: 13px;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--wf-text-2);
    }

    .wf-table {
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0;
      font-size: 13px;
    }
    .wf-table th, .wf-table td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--wf-border);
    }
    .wf-table th {
      font-family: 'Space Mono', monospace;
      font-size: 10px;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: var(--wf-text-3);
      font-weight: 400;
    }
    .wf-table td.trunc { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .mono { font-family: 'Space Mono', monospace; }

    .empty {
      color: var(--wf-text-3);
      padding: 16px;
      text-align: center;
      border: 1px dashed var(--wf-border);
      margin: 12px 0;
    }

    .wf-add-provider {
      padding: 16px;
      background: rgba(74, 143, 245, 0.04);
      border: 1px solid var(--wf-border);
      border-radius: 3px;
      margin-top: 16px;
    }

    .wf-panel-footer {
      margin-top: 24px;
      padding-top: 16px;
      border-top: 1px solid var(--wf-border);
      text-align: right;
    }

    .wf-cert-field {
      width: 100%;
      margin-top: 8px;
    }
    .wf-cert-field textarea {
      font-family: 'Space Mono', monospace;
      font-size: 11px;
    }

    .wf-twilio-status {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      padding: 12px;
      margin: 12px 0;
      background: rgba(74, 143, 245, 0.04);
      border: 1px solid var(--wf-border);
      border-radius: 3px;
      font-size: 13px;
    }
    .wf-twilio-status code { font-size: 11px; }
    .wf-twilio-status mat-slide-toggle { margin-left: 8px; }

    .wf-toggle-row {
      padding: 12px;
      border: 1px solid var(--wf-border);
      border-radius: 3px;
      background: rgba(74, 143, 245, 0.04);
    }
    .wf-toggle-row .sub { margin: 8px 0 0; font-size: 12px; }
    .wf-branding-grid { margin-top: 16px; }

    .wf-subhead {
      font-family: 'Syne', sans-serif;
      font-size: 13px;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--wf-text-2);
      margin: 16px 0 8px;
    }
    .wf-color-grid { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
    .wf-color-field {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border: 1px solid var(--wf-border);
      border-radius: 3px;
      background: rgba(74, 143, 245, 0.03);
      font-size: 12px;
      color: var(--wf-text-2);
    }
    .wf-color-field span { min-width: 100px; }
    .wf-color-field input[type="color"] {
      width: 36px;
      height: 28px;
      border: 1px solid var(--wf-border);
      background: transparent;
      cursor: pointer;
      padding: 0;
    }
    .wf-color-field input.hex {
      flex: 1 1 auto;
      background: transparent;
      border: 1px solid var(--wf-border);
      border-radius: 2px;
      color: var(--wf-text);
      padding: 6px 8px;
      font-family: 'Space Mono', monospace;
      font-size: 12px;
      min-width: 90px;
    }
  `]
})
export class TenantsComponent implements OnInit {
  tenants = signal<TenantRow[]>([]);
  /**
   * OIDC clients and SAML SPs, keyed by tenant id and loaded per expanded row.
   * Until 2026-09-11 each was ONE list, loaded once in ngOnInit for whatever
   * tenant the request context resolved to, and drawn under every row -- so
   * the row you were looking at was not the tenant you were editing. Signals,
   * not plain row fields, because this page is zoneless: an HTTP callback that
   * only mutates an object field schedules no change detection.
   */
  oidcByTenant = signal<Record<number, OidcClient[]>>({});
  samlSpsByTenant = signal<Record<number, SamlIdpServiceProvider[]>>({});
  creating = signal(false);
  providerTypes = SUPPORTED_PROVIDERS;

  /**
   * Deployment-wide password baseline, fetched once. A signal rather than a
   * plain field because this page is zoneless — an HTTP callback that only
   * mutates a field schedules no change detection, and the policy table would
   * render "—" forever.
   */
  passwordBaseline = signal<ResolvedPasswordPolicy | null>(null);

  /** The four composition rules, rendered as one row each. */
  readonly compositionRules: ReadonlyArray<{
    key: 'requireUppercase' | 'requireLowercase' | 'requireDigit' | 'requireSymbol';
    label: string;
  }> = [
    { key: 'requireUppercase', label: 'Uppercase letter' },
    { key: 'requireLowercase', label: 'Lowercase letter' },
    { key: 'requireDigit',     label: 'Digit' },
    { key: 'requireSymbol',    label: 'Symbol' },
  ];

  newTenant: Partial<Tenant> = { slug: '', name: '', displayName: '' };

  // The TenantPickerComponent (in the Users / Roles / GroupRoleMappings
  // pages) reads its dropdown options from the same /api/admin/tenants
  // GET that this page hits, but caches them under the
  // 'tenant-picker' key for one minute. Invalidating that key after any
  // create/update/delete here keeps the dropdown in sync the moment the
  // operator navigates to a tenant-scoped page.
  private queryClient = injectQueryClient();

  // OIDC create form fields
  newOidcClient: Partial<OidcClient> = { name: '' };
  newOidcRedirects = '';
  newOidcScopes = 'openid profile email';
  newOidcGrants = 'authorization_code';
  newOidcRequirePkce = true;
  newOidcRequireMfa = false;
  newOidcMaxAge = 0;
  /**
   * The credentials just issued for a client, and the row they belong to.
   * Held until dismissed: a secret is shown exactly once, so it must not
   * depend on the operator reading a modal before it goes.
   */
  issuedCredentials = signal<{ tenantId: number; clientId: string; secret: string | null; note: string } | null>(null);
  /** Masked by default, so a screen-share or a screenshot does not carry it. */
  secretVisible = signal(false);

  /** Blank lets the server generate `wf_client_…`; apps usually want a readable id. */
  newOidcClientId = '';
  newOidcWebOrigins = '';
  newOidcPostLogout = '';
  newOidcRefreshTtl: number | null = null;

  /** id of the client whose edit row is open; null when none is. */
  editOidcId: number | null = null;
  editOidc = { redirects: '', webOrigins: '', postLogout: '', scopes: '', grants: '', refreshTtl: null as number | null, branding: '' };
  /** SPA / native app: PKCE only, no secret. */
  newOidcPublic = false;

  // SAML IdP SP draft
  samlIdpDraft: SamlIdpServiceProvider = this.freshSamlIdpDraft();

  constructor(
    private api: TenantService,
    private oidcApi: OidcClientService,
    private samlIdpApi: SamlIdpService,
    private twilioApi: TenantTwilioService,
    private mfaPolicyApi: TenantMfaPolicyService,
    private snack: MatSnackBar) {}

  ngOnInit() {
    this.refresh();
    this.api.passwordPolicyBaseline().subscribe({
      next: b => this.passwordBaseline.set(b),
      // Non-fatal: the table still renders, the baseline column shows "—".
      // Failing the whole page over a reference value would be worse.
      error: () => this.passwordBaseline.set(null),
    });
  }

  refresh() {
    this.api.list().subscribe({
      next: ts => this.tenants.set(ts.map(t => ({
        ...t,
        draft: this.freshDraft(),
        samlDraft: this.freshSamlDraft(),
        twilioDraft: this.freshTwilioDraft(),
        brandingDraft: this.brandingDraftFrom(t),
        sessionDraft: this.sessionDraftFrom(t),
        passwordDraft: this.passwordDraftFrom(t),
      }))),
      error: err => this.err('Failed to load tenants', err),
    });
  }

  issuedFor(t: TenantRow) {
    const issued = this.issuedCredentials();
    return issued && issued.tenantId === t.id ? issued : null;
  }

  private showIssued(t: TenantRow, clientId: string, secret: string | null, note: string) {
    this.secretVisible.set(false);
    this.issuedCredentials.set({ tenantId: t.id, clientId, secret, note });
  }

  dismissIssued() {
    this.issuedCredentials.set(null);
    this.secretVisible.set(false);
  }

  oidcClientsFor(t: TenantRow): OidcClient[] {
    return this.oidcByTenant()[t.id] ?? [];
  }

  samlSpsFor(t: TenantRow): SamlIdpServiceProvider[] {
    return this.samlSpsByTenant()[t.id] ?? [];
  }

  loadOidcClients(t: TenantRow) {
    this.oidcApi.list(t.slug).subscribe({
      next: cs => this.setOidc(t, cs),
      error: err => this.err(`Failed to load OIDC clients for ${t.slug}`, err),
    });
  }

  loadSamlIdpSps(t: TenantRow) {
    this.samlIdpApi.list(t.slug).subscribe({
      next: sps => this.setSamlSps(t, sps),
      error: err => this.err(`Failed to load SAML service providers for ${t.slug}`, err),
    });
  }

  private setOidc(t: TenantRow, clients: OidcClient[]) {
    this.oidcByTenant.update(m => ({ ...m, [t.id]: clients }));
  }

  private setSamlSps(t: TenantRow, sps: SamlIdpServiceProvider[]) {
    this.samlSpsByTenant.update(m => ({ ...m, [t.id]: sps }));
  }

  private freshDraft(): SocialProvider {
    return { provider: 'GOOGLE', clientId: '', clientSecret: '', scopes: '', enabled: true };
  }

  private brandingDraftFrom(t: Tenant): BrandingDraft {
    const brand: Record<string, string> = {};
    const src = (t.branding as Record<string, unknown> | undefined | null) ?? {};
    for (const [k, v] of Object.entries(src)) {
      if (typeof v === 'string') brand[k] = v;
    }
    return {
      registrationEnabled: t.registrationEnabled !== false,
      passwordRecoveryEnabled: t.passwordRecoveryEnabled !== false,
      emailVerificationRequired: t.emailVerificationRequired !== false,
      returnToCallerEnabled: t.returnToCallerEnabled !== false,
      brand,
    };
  }

  /** Editable copy of the session/contact/claims fields for one tenant row. */
  private sessionDraftFrom(t: Tenant): SessionDraft {
    return {
      accessTtlMs: t.accessTtlMs ?? null,
      refreshTtlMs: t.refreshTtlMs ?? null,
      contactEmail: t.contactEmail ?? '',
      allowedEmailDomains: t.allowedEmailDomains ?? '',
      // Pretty-printed so an operator can read what is already there; the
      // server stores an object, the form edits text.
      customClaims: t.customClaims ? JSON.stringify(t.customClaims, null, 2) : '',
    };
  }

  /** A duration in ms, said in units a person uses. Blank means inherit. */
  protected humanMs(ms: number | null | undefined): string {
    if (ms === null || ms === undefined || `${ms}`.trim() === '') {
      return 'Blank inherits the deployment default.';
    }
    const n = Number(ms);
    if (!Number.isFinite(n) || n <= 0) return 'Must be a positive number of milliseconds.';
    const s = n / 1000;
    if (s < 120) return `= ${s.toFixed(0)} seconds`;
    const m = s / 60;
    if (m < 120) return `= ${m.toFixed(0)} minutes`;
    const h = m / 60;
    if (h < 48) return `= ${h.toFixed(1)} hours`;
    return `= ${(h / 24).toFixed(1)} days`;
  }

  /**
   * Null when the JSON is usable, else the reason.
   *
   * A method, not computed(): sessionDraft is a plain object mutated by
   * ngModel, so computed() would freeze at its first value.
   */
  protected customClaimsError(t: TenantRow): string | null {
    const raw = (t.sessionDraft?.customClaims ?? '').trim();
    if (!raw) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return 'Not valid JSON.';
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return 'Must be a JSON object, not an array or a bare value.';
    }
    return null;
  }

  saveSessionSettings(t: TenantRow) {
    if (!t.sessionDraft) return;
    if (this.customClaimsError(t)) { this.err(this.customClaimsError(t)!, null); return; }

    const num = (v: unknown) => {
      const str = `${v ?? ''}`.trim();
      // Blank clears the override; the server reads null as "inherit".
      return str === '' ? null : Number(str);
    };
    const patch: Partial<Tenant> = {
      accessTtlMs: num(t.sessionDraft.accessTtlMs),
      refreshTtlMs: num(t.sessionDraft.refreshTtlMs),
      contactEmail: t.sessionDraft.contactEmail?.trim() || null,
      // Always sent, including blank: blank CLEARS the restriction, and
      // omitting it would read as "unchanged" and make a list unremovable.
      allowedEmailDomains: t.sessionDraft.allowedEmailDomains?.trim() ?? '',
      customClaims: t.sessionDraft.customClaims?.trim()
          ? JSON.parse(t.sessionDraft.customClaims) : null,
    };
    this.api.update(t.id, patch).subscribe({
      next: updated => {
        Object.assign(t, updated);
        t.sessionDraft = this.sessionDraftFrom(updated);
        this.ok(`Session settings saved for ${t.slug}`);
      },
      error: err => this.err('Save failed', err),
    });
  }

  resetBrandingDraft(t: TenantRow) {
    t.brandingDraft = this.brandingDraftFrom(t);
  }

  // ---- Password policy ----------------------------------------------

  private passwordDraftFrom(t: Tenant): PasswordPolicyDraft {
    const p = (t.passwordPolicy ?? {}) as PasswordPolicyOverride;
    return {
      // null, not 0 — an empty box must mean "inherit", and 0 would be an
      // override that says something.
      minLength: typeof p.minLength === 'number' ? p.minLength : null,
      maxLength: typeof p.maxLength === 'number' ? p.maxLength : null,
      requireUppercase: p.requireUppercase === true,
      requireLowercase: p.requireLowercase === true,
      requireDigit:     p.requireDigit === true,
      requireSymbol:    p.requireSymbol === true,
    };
  }

  resetPasswordDraft(t: TenantRow) {
    t.passwordDraft = this.passwordDraftFrom(t);
  }

  /** True when the deployment default already demands this rule. */
  baseRequires(key: 'requireUppercase' | 'requireLowercase' | 'requireDigit' | 'requireSymbol'): boolean {
    return this.passwordBaseline()?.[key] === true;
  }

  effectiveRequires(t: TenantRow,
                    key: 'requireUppercase' | 'requireLowercase' | 'requireDigit' | 'requireSymbol'): boolean {
    // Prefer the server's answer; fall back to the local OR so the row is not
    // blank before the first fetch lands.
    return t.effectivePassword?.[key] ?? (this.baseRequires(key) || t.passwordDraft?.[key] === true);
  }

  /**
   * True when the tenant typed a length the baseline overrules. A plain method,
   * not a computed(): the draft is a plain object mutated by ngModel, and on
   * this zoneless page a computed() over a non-signal memoises its first value
   * forever.
   */
  isOverridden(t: TenantRow, field: 'minLength' | 'maxLength'): boolean {
    const base = this.passwordBaseline();
    const typed = t.passwordDraft?.[field];
    if (!base || typeof typed !== 'number') return false;
    return field === 'minLength' ? typed < base.minLength : typed > base.maxLength;
  }

  /**
   * The line under each length box. Says the deployment default, what is
   * actually in force, and — when those disagree — why, because a value that
   * saved successfully and then did nothing is otherwise indistinguishable
   * from a failed save.
   */
  lengthHint(t: TenantRow, field: 'minLength' | 'maxLength'): string {
    const base = this.passwordBaseline();
    if (!base) return 'Blank inherits the deployment default';
    const effective = t.effectivePassword?.[field];
    const parts = [`Default ${base[field]}`];
    if (typeof effective === 'number') parts.push(`in effect ${effective}`);
    if (this.isOverridden(t, field)) {
      parts.push(field === 'minLength'
        ? 'your value is weaker, so it is ignored'
        : 'your value is looser, so it is ignored');
    }
    return parts.join(' · ');
  }

  ruleHint(t: TenantRow,
           key: 'requireUppercase' | 'requireLowercase' | 'requireDigit' | 'requireSymbol'): string {
    if (this.baseRequires(key)) {
      return 'Required by the deployment default — cannot be switched off here';
    }
    return this.effectiveRequires(t, key)
      ? 'Required for this tenant'
      : 'Not required';
  }

  /** Drops the override entirely, so the tenant inherits the deployment default. */
  clearPasswordPolicy(t: TenantRow) {
    // An empty object is the server's signal to store NULL.
    this.persistPasswordPolicy(t, {}, `${t.slug} now inherits the deployment password policy`);
  }

  savePasswordPolicy(t: TenantRow) {
    if (!t.passwordDraft) return;
    const d = t.passwordDraft;
    const override: PasswordPolicyOverride = {};

    // Only send what was actually set. Sending false for an unticked box would
    // be an override meaning "not required", which reads as an attempt to
    // weaken the baseline rather than as silence.
    if (typeof d.minLength === 'number' && !Number.isNaN(d.minLength)) override.minLength = d.minLength;
    if (typeof d.maxLength === 'number' && !Number.isNaN(d.maxLength)) override.maxLength = d.maxLength;
    if (d.requireUppercase) override.requireUppercase = true;
    if (d.requireLowercase) override.requireLowercase = true;
    if (d.requireDigit)     override.requireDigit = true;
    if (d.requireSymbol)    override.requireSymbol = true;

    this.persistPasswordPolicy(t, override, `Password policy saved for ${t.slug}`);
  }

  private persistPasswordPolicy(t: TenantRow, override: PasswordPolicyOverride, message: string) {
    this.api.update(t.id, { passwordPolicy: override }).subscribe({
      next: updated => {
        Object.assign(t, updated);
        t.passwordDraft = this.passwordDraftFrom(updated);
        this.refreshEffectivePolicy(t);
        this.ok(message);
      },
      // The server validates the override and returns its reasons; surfacing
      // them verbatim is more use than "save failed".
      error: err => this.err('Failed to save password policy', err),
    });
  }

  private refreshEffectivePolicy(t: TenantRow) {
    this.api.effectivePasswordPolicy(t.slug).subscribe({
      next: p => {
        t.effectivePassword = p;
        // Zoneless: mutating a row field schedules nothing on its own, so nudge
        // the signal the table is rendered from.
        this.tenants.set([...this.tenants()]);
      },
      error: () => { /* leave the previous value; the row still renders */ },
    });
  }

  saveBranding(t: TenantRow) {
    if (!t.brandingDraft) return;
    const cleaned: Record<string, string> = {};
    for (const [k, v] of Object.entries(t.brandingDraft.brand)) {
      const trimmed = (v ?? '').toString().trim();
      if (trimmed) cleaned[k] = trimmed;
    }
    const patch: Partial<Tenant> = {
      registrationEnabled: t.brandingDraft.registrationEnabled,
      passwordRecoveryEnabled: t.brandingDraft.passwordRecoveryEnabled,
      emailVerificationRequired: t.brandingDraft.emailVerificationRequired,
      returnToCallerEnabled: t.brandingDraft.returnToCallerEnabled,
      branding: cleaned,
    };
    this.api.update(t.id, patch).subscribe({
      next: updated => {
        Object.assign(t, updated);
        t.brandingDraft = this.brandingDraftFrom(updated);
        // Tenant displayName / branding fields surface in the picker
        // dropdown, so refresh that cache when an update lands.
        this.queryClient.invalidateQueries({ queryKey: ['tenant-picker'] });
        this.ok(`Branding saved for ${t.slug}`);
      },
      error: err => this.err('Failed to save branding', err),
    });
  }

  private freshTwilioDraft(): TwilioProvider {
    return { accountSid: '', authToken: '', fromPhone: '', messagingServiceSid: '', enabled: true };
  }

  private freshSamlDraft(): SamlProvider {
    return {
      providerKey: '',
      displayName: '',
      idpEntityId: '',
      idpSsoUrl: '',
      ssoBinding: 'POST' as SamlBinding,
      idpSigningCertificate: '',
      emailAttribute: 'email',
      nameAttribute: 'name',
      wantAssertionsSigned: true,
      wantAuthnRequestSigned: false,
      enabled: true,
    };
  }

  startCreate() {
    this.newTenant = { slug: '', name: '', displayName: '' };
    this.creating.set(true);
  }
  cancelCreate() { this.creating.set(false); }
  saveCreate() {
    this.api.create(this.newTenant).subscribe({
      next: t => {
        // Re-fetch from server rather than splicing into the local
        // signal: the create response doesn't include every derived
        // field the row template renders (samlDraft, brandingDraft,
        // computed enabled flag, etc.) and a server round-trip is the
        // simplest way to keep the displayed list canonical.
        this.refresh();
        this.queryClient.invalidateQueries({ queryKey: ['tenant-picker'] });
        this.creating.set(false);
        this.ok(`Tenant ${t.slug} created`);
      },
      error: err => this.err('Create failed', err),
    });
  }

  deleteTenant(t: TenantRow) {
    if (!confirm(`Delete tenant "${t.slug}"? All its users and provider config will be removed.`)) return;
    this.api.delete(t.id).subscribe({
      next: () => {
        this.refresh();
        this.queryClient.invalidateQueries({ queryKey: ['tenant-picker'] });
        this.ok(`Tenant ${t.slug} deleted`);
      },
      error: err => this.err('Delete failed', err),
    });
  }

  loadProviders(t: TenantRow) {
    // Resolved server-side, so the "In effect" column is the real answer rather
    // than the portal's guess at the merge rules. Fetched on expand because it
    // is one call per opened row, not one per tenant on page load.
    if (!t.effectivePassword) this.refreshEffectivePolicy(t);

    if (t.providers) return;
    t.loadingProviders = true;
    this.api.listProviders(t.id).subscribe({
      next: ps => { t.providers = ps; t.loadingProviders = false; },
      error: err => { t.loadingProviders = false; this.err('Failed to load providers', err); },
    });
    if (!t.samlProviders) {
      this.api.listSamlProviders(t.id).subscribe({
        next: ps => { t.samlProviders = ps; },
        error: err => this.err('Failed to load SAML providers', err),
      });
    }
    if (t.twilio === undefined) {
      this.twilioApi.get(t.id).subscribe({
        next: cfg => {
          t.twilio = cfg;
          t.twilioDraft = cfg
            ? { ...cfg, authToken: '' }
            : this.freshTwilioDraft();
        },
        error: err => this.err('Failed to load Twilio config', err),
      });
    }
    if (t.mfaPolicy === undefined) {
      this.mfaPolicyApi.get(t.id).subscribe({
        next: p => t.mfaPolicy = p ?? this.freshMfaPolicy(),
        error: err => this.err('Failed to load MFA policy', err),
      });
    }
    this.loadOidcClients(t);
    this.loadSamlIdpSps(t);
  }

  private freshMfaPolicy(): MfaPolicy {
    return { enforcement: 'OPTIONAL' as MfaEnforcement, gracePeriodDays: 7, defaultStepupMaxAge: 0 };
  }

  saveMfaPolicy(t: TenantRow) {
    if (!t.mfaPolicy) return;
    this.mfaPolicyApi.upsert(t.id, t.mfaPolicy).subscribe({
      next: saved => { t.mfaPolicy = saved; this.ok('MFA policy saved'); },
      error: err => this.err('Save failed', err),
    });
  }

  // ---- Twilio (SMS MFA) ---------------------------------------------

  saveTwilio(t: TenantRow) {
    const draft = t.twilioDraft!;
    this.twilioApi.upsert(t.id, draft).subscribe({
      next: saved => {
        t.twilio = saved;
        t.twilioDraft = { ...saved, authToken: '' };
        this.ok('Twilio config saved');
      },
      error: err => this.err('Twilio save failed', err),
    });
  }

  deleteTwilio(t: TenantRow) {
    if (!confirm(`Remove Twilio config from ${t.slug}? SMS MFA will stop working for this tenant.`)) return;
    this.twilioApi.delete(t.id).subscribe({
      next: () => {
        t.twilio = null;
        t.twilioDraft = this.freshTwilioDraft();
        this.ok('Twilio config removed');
      },
      error: err => this.err('Twilio delete failed', err),
    });
  }

  toggleTwilio(t: TenantRow, enabled: boolean) {
    if (!t.twilio) return;
    this.twilioApi.upsert(t.id, { ...t.twilio, enabled, authToken: '' }).subscribe({
      next: saved => {
        t.twilio = saved;
        if (t.twilioDraft) t.twilioDraft.enabled = saved.enabled;
      },
      error: err => this.err('Toggle failed', err),
    });
  }

  // ---- SAML providers ---------------------------------------------

  saveSamlProvider(t: TenantRow) {
    const draft = t.samlDraft!;
    if (!draft.providerKey) { this.err('Provider key is required', null); return; }
    this.api.upsertSamlProvider(t.id, draft).subscribe({
      next: saved => {
        t.samlProviders = [
          ...(t.samlProviders ?? []).filter(p => p.providerKey !== saved.providerKey),
          saved,
        ];
        t.samlDraft = this.freshSamlDraft();
        this.ok(`SAML provider ${saved.providerKey} saved`);
      },
      error: err => this.err('SAML save failed', err),
    });
  }

  toggleSamlProvider(t: TenantRow, p: SamlProvider, enabled: boolean) {
    // Send a payload that preserves the existing config — backend treats
    // blank cert as "keep existing", so an enable/disable toggle is safe.
    this.api.upsertSamlProvider(t.id, {
      ...p,
      enabled,
      idpSigningCertificate: '',
    }).subscribe({
      next: saved => { p.enabled = saved.enabled; },
      error: err => this.err('Toggle failed', err),
    });
  }

  removeSamlProvider(t: TenantRow, p: SamlProvider) {
    if (!confirm(`Remove SAML provider ${p.providerKey} from ${t.slug}?`)) return;
    this.api.deleteSamlProvider(t.id, p.providerKey).subscribe({
      next: () => {
        t.samlProviders = (t.samlProviders ?? []).filter(x => x.providerKey !== p.providerKey);
        this.ok(`${p.providerKey} removed`);
      },
      error: err => this.err('Delete failed', err),
    });
  }

  // ---- SAML IdP service providers -----------------------------------

  private freshSamlIdpDraft(): SamlIdpServiceProvider {
    return {
      entityId: '',
      name: '',
      acsUrl: '',
      sloUrl: '',
      spCertificate: '',
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      enabled: true,
    };
  }

  createSamlIdpSp(t: TenantRow) {
    if (!this.samlIdpDraft.entityId) { this.err('Entity ID is required', null); return; }
    if (!this.samlIdpDraft.acsUrl) { this.err('ACS URL is required', null); return; }
    this.samlIdpApi.create(this.samlIdpDraft, t.slug).subscribe({
      next: created => {
        this.setSamlSps(t, [...this.samlSpsFor(t), created]);
        this.samlIdpDraft = this.freshSamlIdpDraft();
        this.ok(`SAML SP ${created.entityId} registered in ${t.slug}`);
      },
      error: err => this.err('Create failed', err),
    });
  }

  /**
   * PUT a partial change to one SP and swap the saved row into the signal.
   * On failure the toggle is put back, since its visual state has already
   * flipped and would otherwise disagree with the server.
   */
  private updateSamlIdpSp(t: TenantRow, sp: SamlIdpServiceProvider,
                          patch: Partial<SamlIdpServiceProvider>, event?: MatSlideToggleChange) {
    if (!sp.id) return;
    this.samlIdpApi.update(sp.id, patch, t.slug).subscribe({
      next: saved => {
        this.setSamlSps(t, this.samlSpsFor(t).map(x => x.id === saved.id ? saved : x));
        this.ok(`SP ${saved.entityId} updated`);
      },
      error: err => {
        if (event) event.source.checked = !event.checked;
        this.err('Update failed', err);
      },
    });
  }

  setSpRequiresSignedRequests(t: TenantRow, sp: SamlIdpServiceProvider, event: MatSlideToggleChange) {
    if (event.checked && !confirm(
        `Require signed AuthnRequests from ${sp.entityId}?

`
        + 'Unsigned requests from this SP will be rejected from now on. Confirm the SP already signs.')) {
      event.source.checked = false;
      return;
    }
    this.updateSamlIdpSp(t, sp, { wantAuthnRequestSigned: event.checked }, event);
  }

  setSpEncryptAssertions(t: TenantRow, sp: SamlIdpServiceProvider, event: MatSlideToggleChange) {
    // Turning it ON needs the SP to hold the matching private key, and
    // turning it OFF sends assertions in the clear. Both are worth a pause.
    const msg = event.checked
      ? `Encrypt assertions to ${sp.entityId}?

`
        + 'The SP must be able to decrypt with the key matching the certificate on file, '
        + 'or every login fails.'
      : `Stop encrypting assertions to ${sp.entityId}?

`
        + 'Assertions will be signed but sent in the clear inside the browser POST.';
    if (!confirm(msg)) { event.source.checked = !event.checked; return; }
    this.updateSamlIdpSp(t, sp, { encryptAssertions: event.checked }, event);
  }

  setSpEntityIdIssuer(t: TenantRow, sp: SamlIdpServiceProvider, event: MatSlideToggleChange) {
    // The most breaking switch on this page: the SP matches Issuer against a
    // configured string, so flipping it first rejects every assertion.
    const next = event.checked
      ? 'the entityID published in this tenant\'s IdP metadata'
      : `the legacy "${t.slug}-idp"`;
    if (!confirm(`Send ${next} as Issuer to ${sp.entityId}?\n\n`
        + 'Reconfigure the SP to expect this issuer FIRST, or it will reject every login.')) {
      event.source.checked = !event.checked;
      return;
    }
    this.updateSamlIdpSp(t, sp, { useEntityIdAsIssuer: event.checked }, event);
  }

  setSpContextFromSession(t: TenantRow, sp: SamlIdpServiceProvider, event: MatSlideToggleChange) {
    // On: clear the pin so the SP is told how the user really signed in.
    // Off: pin the legacy password value. An SP that only accepts that value
    // breaks the first time one of its users signs in with a security key.
    if (event.checked && !confirm(
        `Report the real sign-in method to ${sp.entityId}?

`
        + 'Users who sign in with MFA will be sent a stronger authentication context than '
        + 'PasswordProtectedTransport. Confirm the SP accepts it.')) {
      event.source.checked = false;
      return;
    }
    this.updateSamlIdpSp(t, sp,
      { authnContextOverride: event.checked ? '' : AUTHN_CONTEXT_PASSWORD_PROTECTED }, event);
  }

  setMetadataWantsSignedRequests(t: TenantRow, wanted: boolean) {
    this.api.update(t.id, { samlWantAuthnRequestsSigned: wanted }).subscribe({
      next: updated => {
        t.samlWantAuthnRequestsSigned = updated.samlWantAuthnRequestsSigned;
        this.ok(`IdP metadata for ${t.slug} now says WantAuthnRequestsSigned="${wanted}"`);
      },
      error: err => this.err('Failed to update IdP metadata setting', err),
    });
  }

  removeSamlIdpSp(t: TenantRow, sp: SamlIdpServiceProvider) {
    if (!sp.id) return;
    if (!confirm(`Remove SAML service provider ${sp.entityId} from ${t.slug}?`)) return;
    this.samlIdpApi.delete(sp.id, t.slug).subscribe({
      next: () => {
        this.setSamlSps(t, this.samlSpsFor(t).filter(x => x.id !== sp.id));
        this.ok(`SP ${sp.entityId} removed`);
      },
      error: err => this.err('Delete failed', err),
    });
  }

  copyIdpMetadataUrl(t: TenantRow) {
    const url = `${environment.apiBaseUrl}/t/${t.slug}/saml2/idp/metadata`;
    this.copy(url);
  }

  // ---- OIDC clients -----------------------------------------------
  // Every call names the row's tenant (t.slug). The page-level picker is not
  // consulted: a client drawn under a tenant's row is created in that tenant.

  /**
   * A hint that changes with the form, because the requirement does.
   *
   * This is a method, not a `computed()`: the fields it reads are plain
   * strings bound with `[(ngModel)]`, and `computed()` only re-evaluates when
   * a tracked *signal* changes. Memoising this to its first value is the
   * zoneless trap that killed the Service Accounts Create button in PR #24.
   */
  /**
   * A method, not computed(): newOidcRefreshTtl is a plain field bound with
   * ngModel, so computed() would memoise its first value.
   */
  refreshTtlHint(): string {
    const raw = `${this.newOidcRefreshTtl ?? ''}`.trim();
    if (raw === '') return 'Blank inherits the tenant, then the instance default.';
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) return 'Must be a positive number of seconds.';
    // A decimal only when there is one: "14 days", not "14.0 days".
    const plain = (v: number) => (Number.isInteger(v) ? `${v}` : v.toFixed(1));
    const days = n / 86400;
    if (days >= 1) return `= ${plain(days)} day${days === 1 ? '' : 's'}`;
    const hours = n / 3600;
    if (hours >= 1) return `= ${plain(hours)} hour${hours === 1 ? '' : 's'}`;
    return `= ${n} second${n === 1 ? '' : 's'}`;
  }

  webOriginHint(): string {
    const redirects = this.splitWords(this.newOidcRedirects);
    if (!this.newOidcPublic) {
      return 'Not needed: a confidential client calls the token endpoint server-side.';
    }
    const derived = originsFor(redirects);
    if (!derived.length) {
      return 'Not needed: a loopback or private-use redirect makes no cross-origin browser calls.';
    }
    return this.newOidcWebOrigins.trim()
        ? 'Required for a browser client, or every call is blocked by CORS.'
        : `Required. Leave blank and ${derived.join(' ')} will be used.`;
  }

  createOidcClient(t: TenantRow) {
    const redirectUris = this.splitWords(this.newOidcRedirects);
    let webOrigins = this.splitWords(this.newOidcWebOrigins);

    // Derive the origin rather than refusing and asking. The server requires
    // one for a public browser client (PR #126), and it is all but always the
    // redirect URI's own origin -- so demanding it be retyped turns a guard
    // against silent breakage into a different kind of dead end. An explicit
    // value always wins; this only fills a blank.
    if (!webOrigins.length && needsWebOrigin(this.newOidcPublic, redirectUris, webOrigins)) {
      webOrigins = originsFor(redirectUris);
    }

    const dto: OidcClient = {
      clientId:     this.newOidcClientId.trim(), // blank = server generates
      name:         this.newOidcClient.name,
      redirectUris,
      scopes:       this.splitWords(this.newOidcScopes),
      grantTypes:   this.splitWords(this.newOidcGrants),
      // A public client has no secret; PKCE is its only proof of possession.
      requirePkce:  this.newOidcPublic || this.newOidcRequirePkce,
      requireMfa:   this.newOidcRequireMfa,
      maxAuthenticationAgeSeconds: this.newOidcMaxAge,
      publicClient: this.newOidcPublic,
      webOrigins,
      postLogoutRedirectUris: this.splitWords(this.newOidcPostLogout),
    };
    // Omitted rather than sent as null when blank: on create, absent means
    // inherit, and the server refuses a non-positive value outright.
    const ttl = `${this.newOidcRefreshTtl ?? ''}`.trim();
    if (ttl !== '') dto.refreshTokenTtlSeconds = Number(ttl);
    if (!dto.redirectUris.length) { this.err('At least one redirect URI is required', null); return; }
    this.oidcApi.create(dto, t.slug).subscribe({
      next: created => {
        this.setOidc(t, [...this.oidcClientsFor(t), created]);
        this.newOidcClient = { name: '' };
        this.newOidcClientId = '';
        this.newOidcPublic = false;
        this.newOidcRedirects = '';
        this.newOidcWebOrigins = '';
        this.newOidcPostLogout = '';
        this.newOidcRefreshTtl = null;
        this.newOidcRequireMfa = false;
        this.newOidcMaxAge = 0;
        // Shown in the page, not an alert: a secret that appears once must be
        // selectable and must survive a stray keypress.
        this.showIssued(t, created.clientId, created.clientSecret ?? null,
            created.clientSecret
                ? `Created in ${t.slug}. This is the only time the secret is shown — store it now.`
                : `Created in ${t.slug}. No secret is issued to a public client; it authenticates with PKCE.`);
      },
      error: err => this.err('Create failed', err),
    });
  }

  startEditOidc(c: OidcClient) {
    this.editOidcId = c.id ?? null;
    this.editOidc = {
      redirects:  (c.redirectUris || []).join(' '),
      webOrigins: (c.webOrigins || []).join(' '),
      postLogout: (c.postLogoutRedirectUris || []).join(' '),
      scopes:     (c.scopes || []).join(' '),
      grants:     (c.grantTypes || []).join(' '),
      refreshTtl: c.refreshTokenTtlSeconds ?? null,
      branding: c.branding ? JSON.stringify(c.branding, null, 2) : '',
    };
  }

  cancelEditOidc() {
    this.editOidcId = null;
  }

  /**
   * Null when the branding JSON is usable, else why not. A method, not
   * computed(): editOidc is a plain object mutated by ngModel.
   */
  protected editOidcBrandingError(): string | null {
    const raw = (this.editOidc.branding ?? '').trim();
    if (!raw) return null;
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { return 'Not valid JSON.'; }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return 'Must be a JSON object, not an array or a bare value.';
    }
    return null;
  }

  saveEditOidc(t: TenantRow, c: OidcClient) {
    if (!c.id) return;
    if (this.editOidcBrandingError()) { this.err(this.editOidcBrandingError()!, null); return; }
    const redirectUris = this.splitWords(this.editOidc.redirects);
    const webOrigins   = this.splitWords(this.editOidc.webOrigins);

    if (!redirectUris.length) { this.err('At least one redirect URI is required', null); return; }

    // Catch this here as well as at the server. The server's refusal is
    // correct but arrives after the round trip, and this is the exact change
    // -- clearing a browser client's origins -- that leaves a client that
    // registers fine and then signs nobody in.
    if (needsWebOrigin(!!c.publicClient, redirectUris, webOrigins)) {
      this.err(`A public client redirecting to a browser URL needs a web origin. `
          + `Use ${originsFor(redirectUris).join(' ')} unless the app is served elsewhere.`, null);
      return;
    }

    // Every field is sent, because the form showed every field: anything the
    // administrator cleared was cleared deliberately. Partial updates are for
    // callers that did not display what they are not changing.
    const patch: Partial<OidcClient> = {
      redirectUris,
      webOrigins,
      postLogoutRedirectUris: this.splitWords(this.editOidc.postLogout),
      scopes:     this.splitWords(this.editOidc.scopes),
      grantTypes: this.splitWords(this.editOidc.grants),
    };
    if (this.editOidc.refreshTtl != null && `${this.editOidc.refreshTtl}`.trim() !== '') {
      patch.refreshTokenTtlSeconds = Number(this.editOidc.refreshTtl);
    }
    // Always sent: {} is how the override is CLEARED, and omitting it would
    // read as "unchanged" and make a client's branding unremovable.
    const rawBranding = (this.editOidc.branding ?? '').trim();
    patch.branding = rawBranding ? JSON.parse(rawBranding) : {};

    this.oidcApi.update(c.id, patch, t.slug).subscribe({
      next: updated => {
        this.setOidc(t, this.oidcClientsFor(t).map(x => (x.id === updated.id ? updated : x)));
        this.editOidcId = null;
        this.ok(`${updated.clientId} updated in ${t.slug}.`);
      },
      error: err => this.err('Update failed', err),
    });
  }

  rotateOidcSecret(t: TenantRow, c: OidcClient) {
    if (!c.id) return;
    if (!confirm(`Rotate the secret for ${c.clientId} in ${t.slug}? Existing integrations will stop working until updated.`)) return;
    this.oidcApi.rotateSecret(c.id, t.slug).subscribe({
      next: rotated => {
        this.showIssued(t, c.clientId, rotated.clientSecret ?? null,
            `Rotated in ${t.slug}. The previous secret stopped working immediately — `
            + `update every deployment that uses it.`);
      },
      error: err => this.err('Rotate failed', err),
    });
  }

  removeOidcClient(t: TenantRow, c: OidcClient) {
    if (!c.id) return;
    if (!confirm(`Delete OIDC client ${c.clientId} from ${t.slug}? Tokens issued to it will continue to verify until they expire.`)) return;
    this.oidcApi.delete(c.id, t.slug).subscribe({
      next: () => {
        this.setOidc(t, this.oidcClientsFor(t).filter(x => x.id !== c.id));
        this.ok('Client deleted');
      },
      error: err => this.err('Delete failed', err),
    });
  }

  copy(text: string) {
    navigator.clipboard.writeText(text).then(
      () => this.ok('Copied'),
      () => this.err('Copy failed', null),
    );
  }

  private splitWords(s: string): string[] {
    return s.split(/[\s,]+/).map(v => v.trim()).filter(v => !!v);
  }

  saveProvider(t: TenantRow) {
    const draft = t.draft!;
    if (!draft.clientId) { this.err('Client ID is required', null); return; }
    this.api.upsertProvider(t.id, draft).subscribe({
      next: saved => {
        t.providers = [
          ...(t.providers ?? []).filter(p => p.provider !== saved.provider),
          saved,
        ];
        t.draft = this.freshDraft();
        this.ok(`${saved.provider} saved for ${t.slug}`);
      },
      error: err => this.err('Save failed', err),
    });
  }

  toggleProvider(t: TenantRow, p: SocialProvider, enabled: boolean) {
    this.api.upsertProvider(t.id, { ...p, enabled, clientSecret: '' }).subscribe({
      next: saved => { p.enabled = saved.enabled; },
      error: err => this.err('Toggle failed', err),
    });
  }

  removeProvider(t: TenantRow, p: SocialProvider) {
    if (!confirm(`Remove ${p.provider} from ${t.slug}?`)) return;
    this.api.deleteProvider(t.id, p.provider).subscribe({
      next: () => {
        t.providers = (t.providers ?? []).filter(x => x.provider !== p.provider);
        this.ok(`${p.provider} removed`);
      },
      error: err => this.err('Delete failed', err),
    });
  }

  private ok(msg: string) { this.snack.open(msg, 'OK', { duration: 3000 }); }
  private err(msg: string, err: any) {
    console.error(msg, err);
    const detail = apiErrorMessage(err);
    this.snack.open(`${msg}${detail ? ': ' + detail : ''}`, 'Dismiss', { duration: 5000 });
  }
}
