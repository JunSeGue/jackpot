import { apiNoToken } from "../../token/AxiosConfig";

// 아이디 찾기 API 호출 함수
export const findId = async (user) => {
  try {
    const response = await apiNoToken.get("member/findId", {
      params: { name: user.name, phone: user.phone },
    });

    if (response.data) {
      return response.data; // 성공 시 이메일 반환
    } else {
      throw new Error("일치하는 사용자를 찾을 수 없습니다.");
    }
  } catch (error) {
    if (error.response && error.response.status === 404) {
      throw new Error("일치하는 사용자를 찾을 수 없습니다.");
    } else {
      throw new Error("오류가 발생했습니다. 다시 시도해주세요.");
    }
  }
};

// 이메일 인증 코드 전송 API 호출 함수
export const sendAuthCode = async (email) => {
  try {
    const response = await apiNoToken.get("sendEmail", { params: { email } });

    // 서버 연결 확인 (200번대 응답 확인)
    if (response.status >= 200 && response.status < 300) {
      console.log("서버와의 연결이 성공적으로 이루어졌습니다.");
      return true; // 연결 성공 시 true 반환
    } else {
      console.warn("서버와의 연결에 문제가 발생했습니다.");
      return false; // 연결 실패 시 false 반환
    }
  } catch (error) {
    console.error("서버와의 연결에 실패했습니다:", error);
    return false; // 연결 오류 시 false 반환
  }
};

// 인증 코드 확인 API 호출 함수
export const verifyAuthCode = async (name, code, email) => {
  try {
    const response = await apiNoToken.post("/checkVerificationCode", {
      name,
      code,
      email,
    });

    if (response.status === 200) {
      return true; // 인증 성공
    } else {
      throw new Error("인증 코드가 일치하지 않습니다.");
    }
  } catch (error) {
    console.error(error);
    throw new Error("인증에 실패했습니다. 다시 시도해주세요.");
  }
};

// 비밀번호 재설정 API 호출 함수
export const resetPassword = async (email, pwd) => {
  try {
    const response = await apiNoToken.patch("member/resetPwd", { email, pwd });

    if (response.status === 200) {
      return {
        success: true,
        message: "비밀번호가 성공적으로 변경되었습니다.",
      };
    } else if (response.status === 400) {
      return {
        success: false,
        message: "잘못된 요청입니다. 이메일을 확인하세요.",
      };
    } else {
      return { success: false, message: "알 수 없는 오류가 발생했습니다." };
    }
  } catch (error) {
    return {
      success: false,
      message: "비밀번호 변경에 실패했습니다. 다시 시도해주세요.",
    };
  }
};
