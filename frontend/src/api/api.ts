import axios, { AxiosInstance, AxiosRequestConfig, AxiosError, InternalAxiosRequestConfig } from 'axios';
import JSONbig from 'json-bigint';

const localApi = axios.create({
  baseURL: typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.host}/api/v1` : '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,  // P0-2: Send httpOnly cookies automatically
  validateStatus: (status) => {
    return status >= 200 && status < 300;
  },
  transformResponse: [(data) => JSONbig.parse(data)]
});

// Удаляем глобальную переменную accessToken - будем всегда читать из localStorage
const getApiInstance = () => {
  return localApi;
};

// Check if the URL is for the refresh token endpoint to avoid infinite loops
const isRefreshTokenEndpoint = (url: string): boolean => {
  return url.includes("/auth/refresh");
};

const setupInterceptors = (apiInstance: AxiosInstance) => {
  apiInstance.interceptors.request.use(
    (config: InternalAxiosRequestConfig): InternalAxiosRequestConfig => {
      // P0-2: Tokens are now in httpOnly cookies, sent automatically by browser
      // No need to manually set Authorization header
      // The cookies are sent automatically with withCredentials: true
      return config;
    },
    (error: AxiosError): Promise<AxiosError> => Promise.reject(error)
  );

  apiInstance.interceptors.response.use(
    (response) => response,
    async (error: AxiosError): Promise<unknown> => {
      const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

      // P0-2: Token refresh with httpOnly cookies
      // Only refresh token when we get a 401/403 error (token is invalid/expired)
      if (error.response?.status && [401, 403].includes(error.response.status) &&
          !originalRequest._retry &&
          originalRequest.url && !isRefreshTokenEndpoint(originalRequest.url)) {
        originalRequest._retry = true;

        try {
          // P0-2: Refresh token is in httpOnly cookie, sent automatically
          // Note: Backend needs to read refresh_token from cookie
          const response = await localApi.post(`/auth/refresh`, {
            // Empty body - refresh token comes from cookie
          });

          // New tokens are set as httpOnly cookies by backend
          // No need to manually store them
          if (response.status === 200) {
            // Retry the original request - new cookies are already set
            return getApiInstance()(originalRequest);
          } else {
            throw new Error('Failed to refresh token');
          }
        } catch (err) {
          // P0-2: Clear any client-side state and redirect
          // Note: httpOnly cookies can only be cleared by backend or expiration
          window.location.href = '/login';
          return Promise.reject(err);
        }
      }

      return Promise.reject(error);
    }
  );
};

setupInterceptors(localApi);

const api = {
  request: (config: AxiosRequestConfig) => {
    const apiInstance = getApiInstance();
    return apiInstance(config);
  },
  get: (url: string, config?: AxiosRequestConfig) => {
    const apiInstance = getApiInstance();
    return apiInstance.get(url, config);
  },
  post: (url: string, data?: unknown, config?: AxiosRequestConfig) => {
    const apiInstance = getApiInstance();
    return apiInstance.post(url, data, config);
  },
  put: (url: string, data?: unknown, config?: AxiosRequestConfig) => {
    const apiInstance = getApiInstance();
    return apiInstance.put(url, data, config);
  },
  delete: (url: string, config?: AxiosRequestConfig) => {
    const apiInstance = getApiInstance();
    return apiInstance.delete(url, config);
  },
};

export default api;
