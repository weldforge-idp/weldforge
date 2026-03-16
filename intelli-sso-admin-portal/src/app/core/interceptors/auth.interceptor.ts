import { HttpInterceptorFn } from '@angular/common/http';
import { environment } from '../../../environments/environment';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = localStorage.getItem('access_token');
  return next(req.clone({
    setHeaders: {
      Authorization: token ? `Bearer ${token}` : '',
      'x-app-authorization': environment.appApiKey
    }
  }));
};