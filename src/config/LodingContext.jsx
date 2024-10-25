import React, { createContext, useContext, useState, useEffect } from "react";

// Context 생성
const LoadingContext = createContext();

export const useLoading = () => useContext(LoadingContext);

export const LoadingProvider = ({ children }) => {
  const [loading, setLoading] = useState(false); // 초기 상태는 false

  // 로딩 상태가 변경될 때마다 로그 출력
  useEffect(() => {
    console.log("Loading State Changed:", loading);
  }, [loading]);

  return (
    <LoadingContext.Provider value={{ loading, setLoading }}>
      {children}
    </LoadingContext.Provider>
  );
};
