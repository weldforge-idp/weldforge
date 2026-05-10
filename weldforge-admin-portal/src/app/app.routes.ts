import { Routes } from '@angular/router';
import { LoginComponent } from './features/login/login.component';
import { UsersComponent } from './features/users/users.component';
import { RolesComponent } from './features/roles/roles.component';
import { TenantsComponent } from './features/tenants/tenants.component';
import { SecurityComponent } from './features/security/security.component';
import { AuditComponent } from './features/audit/audit.component';
import { GroupRoleMappingsComponent } from './features/group-role-mappings/group-role-mappings.component';
import { ServiceAccountsComponent } from './features/service-accounts/service-accounts.component';
import { ForgotPasswordComponent } from './features/auth/forgot-password.component';
import { ResetPasswordComponent } from './features/auth/reset-password.component';
import { RegisterComponent } from './features/auth/register.component';
import { VerifyEmailComponent } from './features/auth/verify-email.component';
import { authGuard } from './core/guards/auth.guard';

export const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'forgot-password', component: ForgotPasswordComponent },
  { path: 'reset-password', component: ResetPasswordComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'verify-email', component: VerifyEmailComponent },
  { path: 'tenants', component: TenantsComponent, canActivate: [authGuard] },
  { path: 'users', component: UsersComponent, canActivate: [authGuard] },
  { path: 'roles', component: RolesComponent, canActivate: [authGuard] },
  { path: 'security', component: SecurityComponent, canActivate: [authGuard] },
  { path: 'audit', component: AuditComponent, canActivate: [authGuard] },
  { path: 'group-role-mappings', component: GroupRoleMappingsComponent, canActivate: [authGuard] },
  { path: 'service-accounts', component: ServiceAccountsComponent, canActivate: [authGuard] },
  { path: '', redirectTo: 'tenants', pathMatch: 'full' },
  { path: '**', redirectTo: 'tenants' }
];