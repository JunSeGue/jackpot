import React, { useContext, useEffect } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { AuthContext } from "./AuthContext";

const ProtectedRoute = ({ allowedRoles }) => {
  const { isAuthenticated, userRole } = useContext(AuthContext);
  console.log(userRole);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAuthenticated) {
      // 사용자가 로그인되지 않은 경우 로그인 페이지로 리디렉션
      alert("로그인 후 이용 가능한 기능입니다.");
      navigate("/signIn", {
        replace: true,
        state: { redirectedFrom: location.pathname },
      });
    } else if (!allowedRoles.includes(userRole)) {
      // 사용자가 해당 역할에 포함되지 않은 경우, 접근 불가 페이지로 리디렉션
      alert("접근이 허용되지 않은 회원입니다.");
      navigate("/");
      if(location.pathname === "/auction/bid"){
        navigate("/auction");
      }  
    }
      
  }, [isAuthenticated, userRole, allowedRoles, navigate, location]);

  return isAuthenticated && allowedRoles.includes(userRole) ? <Outlet /> : null;
};

export default ProtectedRoute;
