import React, { createContext, useState } from "react";
import { jwtDecode } from "jwt-decode";
import { useNavigate } from "react-router-dom";
import { logout as requestLogout } from "./Logout";

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const navigate = useNavigate();
  const token = sessionStorage.getItem("accessToken");
  const decodedToken = token ? jwtDecode(token) : null;

  const initialRole = decodedToken?.role || "";
  const initialIsAuthenticated = Boolean(token);
  const initialIsAdmin = initialRole === "ROLE_ADMIN";
  const initialIsPremium = initialRole === "ROLE_PREMIUM";

  const [isAuthenticated, setIsAuthenticated] = useState(
    initialIsAuthenticated
  );
  const [userRole, setUserRole] = useState(initialRole);
  const [isAdmin, setIsAdmin] = useState(initialIsAdmin);
  const [isPremium, setIsPremium] = useState(initialIsPremium);

  const login = (accessToken, redirectPath = "/") => {
    sessionStorage.setItem("accessToken", accessToken);
    const decoded = jwtDecode(accessToken);
    console.log(decoded);
    setIsAuthenticated(true);
    setUserRole(decoded.role || "ROLE_USER");
    setIsAdmin(decoded.role === "ROLE_ADMIN");
    setIsPremium(decoded.role === "ROLE_PREMIUM");
    navigate(decoded.role === "ROLE_ADMIN" ? "/admin" :"/", redirectPath, {
      replace: true,
    });
  };

  const logout = async () => {
    await requestLogout();
    sessionStorage.removeItem("accessToken");
    setIsAuthenticated(false);
    setUserRole("");
    setIsAdmin(false);
    setIsPremium(false);
  };

  return (
    <AuthContext.Provider
      value={{ isAuthenticated, userRole, isAdmin, isPremium, login, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
};
