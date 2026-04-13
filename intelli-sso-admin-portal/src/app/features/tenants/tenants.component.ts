import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
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
  TenantService
} from '../../core/services/tenant.service';
import { OidcClient, OidcClientService } from '../../core/services/oidc-client.service';
import { SamlIdpServiceProvider, SamlIdpService } from '../../core/services/saml-idp.service';
import { environment } from '../../../environments/environment';

interface TenantRow extends Tenant {
  providers?: SocialProvider[];
  samlProviders?: SamlProvider[];
  loadingProviders?: boolean;
  expanded?: boolean;
  draft?: SocialProvider;
  samlDraft?: SamlProvider;
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
        <mat-expansion-panel *ngFor="let t of tenants()"
                             (opened)="loadProviders(t)" class="wf-panel">
          <mat-expansion-panel-header>
            <mat-panel-title>
              <span class="slug mono">{{ t.slug }}</span>
              <span class="name">{{ t.displayName || t.name }}</span>
            </mat-panel-title>
            <mat-panel-description>
              <span class="status" [class.on]="t.enabled">{{ t.enabled ? 'enabled' : 'disabled' }}</span>
              <span *ngIf="t.providers?.length" class="chips">
                <mat-chip *ngFor="let p of t.providers" [class.off]="!p.enabled">{{ p.provider }}</mat-chip>
              </span>
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

            <!-- ==================== OIDC clients ==================== -->
            <section class="wf-section">
              <h4>OIDC relying parties</h4>
              <p class="sub">Apps that authenticate <em>via</em> WeldForge as their OpenID Connect identity provider. Each client gets its own secret and may register multiple redirect URIs.</p>

              <table *ngIf="oidcClients().length" class="wf-table">
                <thead>
                  <tr><th>client_id</th><th>Name</th><th>Redirect URIs</th><th>Scopes</th><th>Grants</th><th>PKCE</th><th></th></tr>
                </thead>
                <tbody>
                  <tr *ngFor="let c of oidcClients()">
                    <td class="mono trunc">{{ c.clientId }}</td>
                    <td>{{ c.name || '—' }}</td>
                    <td class="mono trunc">{{ (c.redirectUris || []).join(', ') }}</td>
                    <td class="mono">{{ (c.scopes || []).join(' ') }}</td>
                    <td class="mono">{{ (c.grantTypes || []).join(' ') }}</td>
                    <td>{{ c.requirePkce ? 'yes' : 'no' }}</td>
                    <td>
                      <button mat-icon-button (click)="rotateOidcSecret(c)" title="Rotate secret">
                        <mat-icon>refresh</mat-icon>
                      </button>
                      <button mat-icon-button color="warn" (click)="removeOidcClient(c)">
                        <mat-icon>delete</mat-icon>
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>

              <div *ngIf="!oidcClients().length" class="empty mono">
                // no OIDC clients configured for this tenant yet
              </div>

              <div class="wf-add-provider">
                <h5>Register a new OIDC client</h5>
                <div class="wf-grid">
                  <mat-form-field appearance="outline">
                    <mat-label>Client name</mat-label>
                    <input matInput [(ngModel)]="newOidcClient.name" placeholder="Acme dashboard">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Redirect URIs (space-separated)</mat-label>
                    <input matInput [(ngModel)]="newOidcRedirects" placeholder="https://app.acme.test/callback">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Scopes</mat-label>
                    <input matInput [(ngModel)]="newOidcScopes" placeholder="openid profile email">
                  </mat-form-field>
                  <mat-form-field appearance="outline">
                    <mat-label>Grant types</mat-label>
                    <input matInput [(ngModel)]="newOidcGrants" placeholder="authorization_code">
                  </mat-form-field>
                </div>
                <div class="wf-actions">
                  <mat-slide-toggle [(ngModel)]="newOidcRequirePkce">Require PKCE</mat-slide-toggle>
                  <span class="spacer"></span>
                  <button mat-raised-button color="primary" (click)="createOidcClient(t)">Create Client</button>
                </div>
              </div>
            </section>

            <!-- ==================== SAML IdP service providers ==================== -->
            <section class="wf-section">
              <h4>SAML IdP — downstream service providers</h4>
              <p class="sub">Apps that receive SAML assertions from WeldForge. Register each SP's entity ID and Assertion Consumer Service URL.</p>

              <table *ngIf="samlIdpSps().length" class="wf-table">
                <thead>
                  <tr><th>Entity ID</th><th>Name</th><th>ACS URL</th><th>Status</th><th>IdP metadata</th><th></th></tr>
                </thead>
                <tbody>
                  <tr *ngFor="let sp of samlIdpSps()">
                    <td class="mono trunc">{{ sp.entityId }}</td>
                    <td>{{ sp.name || '—' }}</td>
                    <td class="mono trunc">{{ sp.acsUrl }}</td>
                    <td>
                      <span class="status" [class.on]="sp.enabled">{{ sp.enabled ? 'enabled' : 'disabled' }}</span>
                    </td>
                    <td>
                      <button mat-icon-button (click)="copyIdpMetadataUrl(t)" title="Copy IdP metadata URL">
                        <mat-icon>content_copy</mat-icon>
                      </button>
                    </td>
                    <td>
                      <button mat-icon-button color="warn" (click)="removeSamlIdpSp(sp)">
                        <mat-icon>delete</mat-icon>
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>

              <div *ngIf="!samlIdpSps().length" class="empty mono">
                // no downstream SAML service providers configured yet
              </div>

              <div class="wf-add-provider">
                <h5>Register a new SAML service provider</h5>
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
                  <button mat-raised-button color="primary" (click)="createSamlIdpSp()">Register SP</button>
                </div>
              </div>
            </section>

            <div class="wf-panel-footer">
              <button mat-stroked-button color="warn" (click)="deleteTenant(t)">
                <mat-icon>delete_forever</mat-icon> Delete Tenant
              </button>
            </div>
          </div>
        </mat-expansion-panel>
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

    .wf-card { padding: 20px; margin-bottom: 20px; }
    .wf-create-card h3 {
      font-family: 'Syne', sans-serif;
      margin: 0 0 16px;
    }

    .wf-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
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
  `]
})
export class TenantsComponent implements OnInit {
  tenants = signal<TenantRow[]>([]);
  oidcClients = signal<OidcClient[]>([]);
  samlIdpSps = signal<SamlIdpServiceProvider[]>([]);
  creating = signal(false);
  providerTypes = SUPPORTED_PROVIDERS;

  newTenant: Partial<Tenant> = { slug: '', name: '', displayName: '' };

  // OIDC create form fields
  newOidcClient: Partial<OidcClient> = { name: '' };
  newOidcRedirects = '';
  newOidcScopes = 'openid profile email';
  newOidcGrants = 'authorization_code';
  newOidcRequirePkce = true;

  // SAML IdP SP draft
  samlIdpDraft: SamlIdpServiceProvider = this.freshSamlIdpDraft();

  constructor(
    private api: TenantService,
    private oidcApi: OidcClientService,
    private samlIdpApi: SamlIdpService,
    private snack: MatSnackBar) {}

  ngOnInit() {
    this.refresh();
    this.refreshOidcClients();
    this.refreshSamlIdpSps();
  }

  refresh() {
    this.api.list().subscribe({
      next: ts => this.tenants.set(ts.map(t => ({
        ...t,
        draft: this.freshDraft(),
        samlDraft: this.freshSamlDraft(),
      }))),
      error: err => this.err('Failed to load tenants', err),
    });
  }

  refreshOidcClients() {
    this.oidcApi.list().subscribe({
      next: cs => this.oidcClients.set(cs),
      error: err => this.err('Failed to load OIDC clients', err),
    });
  }

  refreshSamlIdpSps() {
    this.samlIdpApi.list().subscribe({
      next: sps => this.samlIdpSps.set(sps),
      error: err => this.err('Failed to load SAML IdP service providers', err),
    });
  }

  private freshDraft(): SocialProvider {
    return { provider: 'GOOGLE', clientId: '', clientSecret: '', scopes: '', enabled: true };
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
        this.tenants.update(ts => [...ts, { ...t, draft: this.freshDraft() }]);
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
        this.tenants.update(ts => ts.filter(x => x.id !== t.id));
        this.ok(`Tenant ${t.slug} deleted`);
      },
      error: err => this.err('Delete failed', err),
    });
  }

  loadProviders(t: TenantRow) {
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
    this.refreshSamlIdpSps();
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

  createSamlIdpSp() {
    if (!this.samlIdpDraft.entityId) { this.err('Entity ID is required', null); return; }
    if (!this.samlIdpDraft.acsUrl) { this.err('ACS URL is required', null); return; }
    this.samlIdpApi.create(this.samlIdpDraft).subscribe({
      next: created => {
        this.samlIdpSps.update(sps => [...sps, created]);
        this.samlIdpDraft = this.freshSamlIdpDraft();
        this.ok(`SAML SP ${created.entityId} registered`);
      },
      error: err => this.err('Create failed', err),
    });
  }

  removeSamlIdpSp(sp: SamlIdpServiceProvider) {
    if (!sp.id) return;
    if (!confirm(`Remove SAML service provider ${sp.entityId}?`)) return;
    this.samlIdpApi.delete(sp.id).subscribe({
      next: () => {
        this.samlIdpSps.update(sps => sps.filter(x => x.id !== sp.id));
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

  createOidcClient(_t: TenantRow) {
    const dto: OidcClient = {
      clientId: '', // server generates
      name: this.newOidcClient.name,
      redirectUris: this.splitWords(this.newOidcRedirects),
      scopes:       this.splitWords(this.newOidcScopes),
      grantTypes:   this.splitWords(this.newOidcGrants),
      requirePkce:  this.newOidcRequirePkce,
    };
    if (!dto.redirectUris.length) { this.err('At least one redirect URI is required', null); return; }
    this.oidcApi.create(dto).subscribe({
      next: created => {
        this.oidcClients.update(cs => [...cs, created]);
        this.newOidcClient = { name: '' };
        this.newOidcRedirects = '';
        // Show the secret in a modal-style alert so the admin captures it once.
        const message = `OIDC client created.\n\n`
          + `client_id:     ${created.clientId}\n`
          + `client_secret: ${created.clientSecret}\n\n`
          + `Save the secret now — it will not be shown again.`;
        window.alert(message);
      },
      error: err => this.err('Create failed', err),
    });
  }

  rotateOidcSecret(c: OidcClient) {
    if (!c.id) return;
    if (!confirm(`Rotate the secret for ${c.clientId}? Existing integrations will stop working until updated.`)) return;
    this.oidcApi.rotateSecret(c.id).subscribe({
      next: rotated => {
        const message = `New client_secret for ${c.clientId}:\n\n${rotated.clientSecret}\n\nSave it now.`;
        window.alert(message);
      },
      error: err => this.err('Rotate failed', err),
    });
  }

  removeOidcClient(c: OidcClient) {
    if (!c.id) return;
    if (!confirm(`Delete OIDC client ${c.clientId}? Tokens issued to it will continue to verify until they expire.`)) return;
    this.oidcApi.delete(c.id).subscribe({
      next: () => {
        this.oidcClients.update(cs => cs.filter(x => x.id !== c.id));
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
    this.snack.open(`${msg}${err?.error?.message ? ': ' + err.error.message : ''}`, 'Dismiss', { duration: 5000 });
  }
}
