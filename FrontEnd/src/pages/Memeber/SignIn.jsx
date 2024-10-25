import React, { useState, useEffect, useContext } from "react";

import "../../login/CSS/Login.css";
import SocialLogin from "../../login/components/SocialLogin";

import InputField from "../../login/components/InputField";
import { useLocation, useNavigate } from "react-router-dom";
import { AuthContext } from "../../token/AuthContext";
import { apiNoToken } from "../../token/AxiosConfig";
import FindMember from "../../login/components/FindMember";

const SignIn = () => {
  const [user, setUser] = useState({ email: "", pwd: "" });
  const location = useLocation();
  const { isAuthenticated } = useContext(AuthContext); // 로그인 상태 확인
  const navigate = useNavigate();
  const { login } = useContext(AuthContext); // 로그인 상태 및 토큰 전달

  // *** 로그인 상태일 경우 메인 페이지로 리다이렉트 ***
  useEffect(() => {
    if (isAuthenticated) {
      navigate("/", { replace: true });
    }
  }, [isAuthenticated, navigate]);
  // ************************************************

  // *** 회원가입한 이메일 적용 하기 ***
  useEffect(() => {
    if (location.state && location.state.email) {
      setUser((prevUser) => ({
        ...prevUser,
        email: location.state.email,
      }));
    }
  }, [location.state]);
  // *****************************

  const handleChange = (event) => {
    setUser({ ...user, [event.target.name]: event.target.value });
  };

  const signIn = async (event) => {
    event.preventDefault(); // 폼 제출 기본 동작 방지

    try {
      const response = await apiNoToken.post("member/signIn", user, {
        withCredentials: true, // 쿠키를 사용하려면 true로 설정
      });

      const { access: accessToken } = response.data;
      if (accessToken) {
        const redirectPath = location.state?.redirectedFrom || "/";
        login(accessToken, redirectPath);
      } else {
        alert("로그인 실패");
      }
    } catch (err) {
      console.error(err);
      alert("로그인 중 오류가 발생했습니다");
    }
  };

  return (
    <div className="wrapper">
      <div className="login-container">
        <div className="heading">Sign In</div>
        <form onSubmit={signIn} className="form">
          <InputField
            type="email"
            name="email"
            placeholder="E-mail"
            value={user.email}
            onChange={handleChange}
            autoComplete="email"
          />
          <InputField
            type="password"
            name="pwd"
            placeholder="Password"
            value={user.pwd}
            onChange={handleChange}
            autoComplete="current-password"
          />
          <input className="button btn_sign" type="submit" value="Sign In" />
        </form>

        <FindMember />

        <SocialLogin />
      </div>
    </div>
  );
};

export default SignIn;
