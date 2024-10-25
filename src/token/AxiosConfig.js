// src/config/AxiosConfig.js
import axios from "axios";
import { SERVER_URL } from "../config/Constants";
import { logout } from "./Logout";

// Named export: 토큰 없이 사용하는 API 인스턴스
export const apiNoToken = axios.create({
  baseURL: SERVER_URL,
  headers: {},
});

apiNoToken.interceptors.request.use(
  (config) => {
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

apiNoToken.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Default export: 토큰이 필요한 API 인스턴스
const apiClient = axios.create({
  baseURL: SERVER_URL,
  withCredentials: true, // 쿠키 포함
});

// 인터셉터 설정 함수

apiClient.interceptors.request.use(
  (config) => {
    const accessToken = sessionStorage.getItem("accessToken");
    if (accessToken) {
      config.headers["Authorization"] = `Bearer ${accessToken}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // 401 에러 처리 및 토큰 재발급
    if (
      error.response &&
      error.response.status === 401 &&
      !originalRequest._retry
    ) {
      originalRequest._retry = true;
      try {
        const response = await axios.post(
          `${SERVER_URL}reissue`,
          {},
          { withCredentials: true }
        );
        const { access: accessToken } = response.data;

        if (accessToken) {
          sessionStorage.setItem("accessToken", accessToken);
          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
          return apiClient(originalRequest); // 원래 요청 재시도
        } else {
          throw new Error("토큰 재발급에 실패했습니다.");
        }
      } catch (err) {
        logout(); // 로그아웃 처리
        return Promise.reject(err);
      }
    }
    return Promise.reject(error);
  }
);

export default apiClient;
