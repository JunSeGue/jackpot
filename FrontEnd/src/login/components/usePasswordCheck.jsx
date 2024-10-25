import { useState, useEffect } from "react";

const usePasswordCheck = (password, confirmPassword) => {
  const [checkMessage, setCheckMessage] = useState("");
  const [messageColor, setMessageColor] = useState("");

  useEffect(() => {
    if (confirmPassword.length > 0) {
      if (password !== confirmPassword) {
        setCheckMessage("비밀번호가 일치하지 않습니다.");
        setMessageColor("red");
      } else {
        setCheckMessage("비밀번호가 일치합니다.");
        setMessageColor("green");
      }
    } else {
      setCheckMessage("");
      setMessageColor("");
    }
  }, [password, confirmPassword]);

  return { checkMessage, messageColor };
};

export default usePasswordCheck;
