import axios, { AxiosRequestConfig, AxiosError, InternalAxiosRequestConfig } from 'axios';
import JSONbig from 'json-bigint';



const localApi = axios.create({
  headers: {
    'Content-Type': 'application/json',
  },
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
  return url.includes("/api/auth/refresh");
};

const setupInterceptors = (apiInstance: typeof axios) => {
  apiInstance.interceptors.request.use(
    (config: InternalAxiosRequestConfig): InternalAxiosRequestConfig => {
      // Всегда читаем токен из localStorage
      const token = localStorage.getItem('accessToken');
      if (token && config.headers) {
        config.headers.Authorization = `Bearer ${token}`;
      }

      return config;
    },
    (error: AxiosError): Promise<AxiosError> => Promise.reject(error)
  );

  apiInstance.interceptors.response.use(
    (response) => response,
    async (error: AxiosError): Promise<unknown> => {
      const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

      // Only refresh token when we get a 401/403 error (token is invalid/expired)
      if (error.response?.status && [401, 403].includes(error.response.status) &&
          !originalRequest._retry &&
          originalRequest.url && !isRefreshTokenEndpoint(originalRequest.url)) {
        originalRequest._retry = true;

        try {
          const refreshToken = localStorage.getItem('refreshToken');
          if (!refreshToken) {
            throw new Error('No refresh token available');
          }

          const response = await localApi.post(`/api/auth/refresh`, {
            refreshToken,
          });

          if (response.data.success && response.data.data) {
            const newAccessToken = response.data.data.accessToken;
            const newRefreshToken = response.data.data.refreshToken;

            // Валидация токенов перед сохранением
            if (typeof newAccessToken === 'string' && newAccessToken.length > 0) {
              localStorage.setItem('accessToken', newAccessToken);
            }
            if (typeof newRefreshToken === 'string' && newRefreshToken.length > 0) {
              localStorage.setItem('refreshToken', newRefreshToken);
            }

            if (originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
            }
          } else {
            throw new Error('Invalid response from refresh token endpoint');
          }
          return getApiInstance()(originalRequest);
        } catch (err) {
          localStorage.removeItem('refreshToken');
          localStorage.removeItem('accessToken');
          // Токены уже удалены из localStorage
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
    const apiInstance = getApiInstance(config.url || '');
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
