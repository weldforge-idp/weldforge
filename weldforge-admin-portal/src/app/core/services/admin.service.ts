import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface User {
  id: number;
  email: string;
  name: string;
  imageUrl?: string;
  provider: string;
  providerId: string;
  /**
   * The tenant Role's NAME, not an object.
   *
   * This was declared as `Role` and never was one: the API has always sent a
   * string here, so `user.role?.name` evaluated to undefined and the portal's
   * Role column showed a dash for every user regardless of their actual role.
   * TypeScript could not catch it because the lie was in this interface.
   */
  role?: string;
  /** The tenant Role's id, for changing the assignment. */
  roleId?: number;
  /** Every role the user holds, by name. Source of truth since V62. */
  roles?: string[];
  /** The same set, by id. */
  roleIds?: number[];
}

export interface Role {
  id: number;
  name: string;
  description?: string;
  responsibilities?: Responsibility[];
}

export interface Responsibility {
  id: number;
  name: string;
}

export interface Environment {
  id: number;
  name: string;
  projectName?: string;
  description?: string;
}

export interface AppClient {
  id: number;
  clientName: string;
  apiKey: string;
  enabled: boolean;
}

@Injectable({ providedIn: 'root' })
export class AdminService {
  private apiUrl = `${environment.apiBaseUrl}/api/admin`;

  constructor(private http: HttpClient) {}

  // Users
  getUsers(): Observable<User[]> {
    return this.http.get<User[]>(`${this.apiUrl}/users`);
  }

  createUser(user: Partial<User>): Observable<User> {
    return this.http.post<User>(`${this.apiUrl}/users`, user);
  }

  // Roles
  getRoles(): Observable<Role[]> {
    return this.http.get<Role[]>(`${this.apiUrl}/roles`);
  }

  createRole(role: Partial<Role>): Observable<Role> {
    return this.http.post<Role>(`${this.apiUrl}/roles`, role);
  }

  // Environments
  getEnvironments(): Observable<Environment[]> {
    return this.http.get<Environment[]>(`${this.apiUrl}/environments`);
  }

  createEnvironment(env: Partial<Environment>): Observable<Environment> {
    return this.http.post<Environment>(`${this.apiUrl}/environments`, env);
  }

  // App Clients
  getAppClients(): Observable<AppClient[]> {
    return this.http.get<AppClient[]>(`${this.apiUrl}/app-clients`);
  }

  createAppClient(client: Partial<AppClient>): Observable<AppClient> {
    return this.http.post<AppClient>(`${this.apiUrl}/app-clients`, client);
  }

  deleteUser(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/users/${id}`);
  }

  resetUserMfa(id: number): Observable<{ removed: number }> {
    return this.http.post<{ removed: number }>(`${this.apiUrl}/users/${id}/reset-mfa`, {});
  }

  /**
   * Assign the application role that flows into the JWT `roles` claim, which
   * is what a relying party drives its own RBAC from. Pass null to clear it.
   *
   * A user holds exactly one role, so this replaces rather than adds.
   */
  setUserRole(id: number, roleId: number | null): Observable<User> {
    return this.http.post<User>(`${this.apiUrl}/users/${id}/role`, { roleId });
  }

  /**
   * Replace the whole set of roles a user holds. Pass [] to clear.
   *
   * Replaces rather than adds, so the caller always states the intended set
   * and there is no separate remove call to forget.
   */
  setUserRoles(id: number, roleIds: number[]): Observable<User> {
    return this.http.put<User>(`${this.apiUrl}/users/${id}/roles`, { roleIds });
  }
}