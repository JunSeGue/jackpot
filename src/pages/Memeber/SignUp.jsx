import React, { useEffect, useState } from "react";
import "../../login/CSS/Login.css";
import { Snackbar } from "@mui/material";
import InputField from "../../login/components/InputField";
import SocialLogin from "../../login/components/SocialLogin";
import { Link, useNavigate } from "react-router-dom";
import { apiNoToken } from "../../token/AxiosConfig";
import usePasswordCheck from "../../login/components/usePasswordCheck";
import {
  formatPhoneNumber,
  getOnlyNumbers,
  validateEmail,
  validateName,
  validateNickname,
  validatePassword,
  validatePhoneNumber,
} from "../../login/components/Validation";
import { useEmailVerification } from "../../login/components/EmailVerification";

const SignUp = () => {
  const navigate = useNavigate();

  const [confirmPassword, setConfirmPassword] = useState("");
  const [duplicateMessage, setDuplicateMessage] = useState("");
  const [isEmailChecked, setIsEmailChecked] = useState(false);
  const [isNickNameChecked, setIsNickNameChecked] = useState(false);
  const [open, setOpen] = useState(false);

  // 추가된 상태: 표시되는 핸드폰 번호를 관리합니다.
  const [displayPhone, setDisplayPhone] = useState("");

  const [formData, setFormData] = useState({
    email: "",
    pwd: "",
    phone: "", // 실제로 저장되는 핸드폰 번호 (숫자만)
    name: "",
    nickName: "",
    address: "",
  });

  const { checkMessage, messageColor } = usePasswordCheck(
    formData.pwd,
    confirmPassword
  );

  const {
    sendVerificationCode,
    verifyCode,
    isEmailVerified,
    verificationCode,
    setVerificationCode,
  } = useEmailVerification(
    formData.email,

    setDuplicateMessage,
    setOpen
  );

  // 유효성 검사 상태
  const [validations, setValidations] = useState({
    email: false,
    pwd: false,
    confirmPassword: false,
    phone: false,
    name: false,
    nickName: false,
  });

  const handleChange = (event) => {
    setFormData({ ...formData, [event.target.name]: event.target.value });
  };

  const handlePasswordChange = (event) => {
    setConfirmPassword(event.target.value);
  };

  // 핸드폰 번호 입력 시 자동 포맷팅 함수
  const handlePhoneChange = (event) => {
    const value = event.target.value;
    const formattedValue = formatPhoneNumber(value); // 포맷팅된 전화번호
    setDisplayPhone(formattedValue);
    setFormData({ ...formData, phone: getOnlyNumbers(value) }); // 숫자만 저장
  };

  const checkNickName = async (event) => {
    event.preventDefault();
    if (!formData.nickName) {
      return alert("닉네임을 입력해주세요");
    }
    try {
      const response = await apiNoToken.get(`member/checkNickName`, {
        params: { nickName: formData.nickName },
      });

      const nickNameIsDuplicate = response.data.isDuplicate;
      setIsNickNameChecked(!nickNameIsDuplicate);
      if (isNickNameChecked) {
        setDuplicateMessage("사용 가능한 닉네임입니다.");
      }
      setOpen(true);
    } catch (error) {
      console.error("닉네임 중복 확인 오류:", error);
      setDuplicateMessage("이미 사용 중인 닉네임입니다.");
      setOpen(true);
    }
  };

  const checkEmail = async (event) => {
    event.preventDefault();
    if (!formData.email) {
      return alert("이메일을 입력해주세요");
    }

    try {
      const response = await apiNoToken.get("member/checkEmail", {
        params: { email: formData.email },
      });

      const emailIsDuplicate = response.data.isDuplicate;
      setIsEmailChecked(!emailIsDuplicate);
      if (!emailIsDuplicate) {
        sendVerificationCode();
      } else {
        setDuplicateMessage("이미 사용중인 이메일입니다.");
      }
      setOpen(true);
    } catch (error) {
      setDuplicateMessage("이미 사용 중인 이메일입니다.");
      setOpen(true);
    }
  };

  const onSubmitHandler = async (event) => {
    event.preventDefault();

    try {
      const response = await apiNoToken.post("member/signUp", formData);

      if (response.status === 201) {
        navigate("/signIn", { state: { email: response.data } });
      }
    } catch (error) {
      console.error("There was an error!", error);
    }
  };

  // 유효성 검사 실행
  useEffect(() => {
    setValidations({
      email: validateEmail(formData.email) && isEmailChecked,
      pwd: validatePassword(formData.pwd),
      confirmPassword: formData.pwd === confirmPassword,
      phone: validatePhoneNumber(formData.phone),
      name: validateName(formData.name),
      nickName: validateNickname(formData.nickName) && isNickNameChecked,
    });
  }, [formData, confirmPassword, isEmailChecked, isNickNameChecked]);

  // 모든 유효성 검사가 통과되었는지 확인합니다.
  const isFormValid = Object.values(validations).every(Boolean);

  return (
    <div className="wrapper">
      <div className="login-container">
        <div className="heading">Sign Up</div>
        <form onSubmit={onSubmitHandler} className="form">
          <div className="check-container">
            <InputField
              type="email"
              name="email"
              placeholder="E-mail"
              value={formData.email}
              onChange={handleChange}
              disabled={isEmailVerified}
            />
            {!isEmailVerified && (
              <input
                className="button"
                type="button"
                value="이메일 중복검사"
                onClick={checkEmail}
                disabled={isEmailVerified}
              />
            )}
          </div>
          {!validations.email && formData.email && (
            <p style={{ color: "red" }}>이메일 중복 검사를 해주세요.</p>
          )}
          {isEmailChecked && !isEmailVerified && (
            <div className="check-container">
              <InputField
                type="text"
                name="verificationCode"
                placeholder="인증 코드 입력"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value)}
              />
              <input
                className="button"
                type="button"
                value="인증 코드 확인"
                onClick={verifyCode}
              />
            </div>
          )}
          <InputField
            type="password"
            name="pwd"
            placeholder="비밀번호"
            value={formData.pwd}
            onChange={handleChange}
          />
          {!validations.pwd && formData.pwd && (
            <p style={{ color: "red" }}>
              비밀번호는 8~20자 사이여야 하며 특수기호가 포함되어야 합니다.
            </p>
          )}
          <InputField
            type="password"
            name="confirmPassword"
            placeholder="비밀번호 확인"
            value={confirmPassword}
            onChange={handlePasswordChange}
          />
          {!validations.confirmPassword && confirmPassword && checkMessage && (
            <p style={{ color: messageColor }}>{checkMessage}</p>
          )}

          <InputField
            type="tel"
            name="phone"
            placeholder="전화번호"
            value={displayPhone} // 표시용 번호 사용
            onChange={handlePhoneChange}
          />
          {!validations.phone && formData.phone && (
            <p style={{ color: "red" }}>핸드폰 번호를 올바르게 입력해주세요.</p>
          )}
          <InputField
            type="text"
            name="name"
            placeholder="이름"
            value={formData.name}
            onChange={handleChange}
          />
          {!validations.name && formData.name && (
            <p style={{ color: "red" }}>이름은 글자만 입력 가능합니다.</p>
          )}

          {/* 닉네임 중복 검사 */}
          <div className="check-container">
            <InputField
              type="text"
              name="nickName"
              placeholder="닉네임"
              value={formData.nickName}
              onChange={handleChange}
              disabled={isNickNameChecked} // 닉네임 중복 확인 완료 시 비활성화
            />
            {!isNickNameChecked && (
              <input
                className="button"
                type="button"
                value="닉네임 중복검사"
                onClick={checkNickName}
              />
            )}
          </div>
          {!validations.nickName && formData.nickName && (
            <p style={{ color: "red" }}>닉네임 중복 검사를 해주세요.</p>
          )}
          <InputField
            type="text"
            name="address"
            placeholder="주소"
            value={formData.address}
            onChange={handleChange}
          />

          <input
            className="button btn_sign"
            type="submit"
            value="Sign Up"
            disabled={!isFormValid}
          />
        </form>
        <div className="go-signUp">
          계정이 있으신가요? <Link to="/signIn">로그인하기</Link>
        </div>
        <SocialLogin />
      </div>
      <Snackbar
        open={open}
        autoHideDuration={3000}
        onClose={() => setOpen(false)}
        message={duplicateMessage}
      />
    </div>
  );
};

export default SignUp;
