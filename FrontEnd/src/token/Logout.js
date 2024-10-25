import { SERVER_URL } from "../config/Constants";
import axios from "axios";

// 로그아웃 함수 정의
export const logout = async () => {
  const accessToken = sessionStorage.getItem("accessToken");

  try {
    // 액세스 토큰이 없으면 에러 발생
    if (!accessToken) {
      throw new Error("액세스 토큰이 없습니다.");
    }

    // 서버로 로그아웃 요청을 보냅니다.
    await axios.post(
      `${SERVER_URL}member/signOut`,
      {},
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
        withCredentials: true,
      }
    );
  } catch (error) {
    console.error("로그아웃 요청 중 오류가 발생했습니다:", error);
  } finally {
    // 세션 스토리지 초기화
    sessionStorage.clear();
    // 페이지를 새로고침하여 상태를 초기화
    window.location.href = "/";
  }
};
