import { Injectable } from '@angular/core';
import { of } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  constructor() { }

  isLoggedIn(): boolean {
    return !!localStorage.getItem('access_token');
  }

  login(credentials: any): any {
    // This is a stub, but we should at least simulate success
    return of(undefined).pipe(
      tap(() => localStorage.setItem('access_token', 'mock-token'))
    );
  }

  logout(): void {
    localStorage.removeItem('access_token');
  }
}
