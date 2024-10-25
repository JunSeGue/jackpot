import React from "react";
import { useLoading } from "./LodingContext";
import styled, { ThemeContext } from "styled-components";
import { ClipLoader } from "react-spinners";

// 오버레이 스타일
const Overlay = styled.div`
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: ${({ theme }) => theme.colors.lightBeige}; /* 연한 베이지 */
  opacity: 0.8;
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 9999;
`;

const GlobalLoading = () => {
  const { loading } = useLoading();
  const theme = React.useContext(ThemeContext);
  if (!loading) return null;

  return (
    <Overlay>
      <ClipLoader color="theme.colors.lightOrange" size={80} />
    </Overlay>
  );
};

export default GlobalLoading;
