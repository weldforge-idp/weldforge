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
  role?: Role;
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
}