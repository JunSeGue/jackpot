import { useState } from "react";
import { apiNoToken } from "../../token/AxiosConfig";

// 이메일 인증 훅
export const useEmailVerification = (email, setDuplicateMessage, setOpen) => {
  const [isEmailVerified, setIsEmailVerified] = useState(false);
  const [verificationCode, setVerificationCode] = useState("");

  const sendVerificationCode = async () => {
    try {
      // 이메일 인증 코드 전송
      await apiNoToken.get("sendEmail", { params: { email } });
      setDuplicateMessage("인증 코드가 이메일로 전송되었습니다.");
      setOpen(true);
    } catch (error) {
      console.error("이메일 인증 코드 전송 오류:", error);
      setDuplicateMessage("인증 코드 전송에 실패했습니다.");
      setOpen(true);
    }
  };

  const verifyCode = async () => {
    try {
      // 입력한 인증 코드로 이메일 인증
      const response = await apiNoToken.post("checkVerificationCode", {
        code: verificationCode,
        email,
      });
      console.log(response);

      if (response.status === 200) {
        setIsEmailVerified(true);
        setDuplicateMessage("이메일 인증이 완료되었습니다.");
      } else {
        setDuplicateMessage("인증 코드가 일치하지 않습니다.");
      }
      setOpen(true);
    } catch (error) {
      console.error("인증 코드 확인 오류:", error);
      setDuplicateMessage("인증코드가 일치하지 않습니다..");
      setOpen(true);
    }
  };

  return {
    sendVerificationCode,
    verifyCode,
    isEmailVerified,
    verificationCode,
    setVerificationCode,
  };
};
