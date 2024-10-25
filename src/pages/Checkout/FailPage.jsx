// FailPage.jsx
import React from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";

export function FailPage() {
  const navigate = useNavigate();
  


  const handleRetry = () => {
    navigate(-1); // 이전 페이지로 이동 (재시도)
  };

  const handleGoHome = () => {
    navigate("/shop"); 
  };

  return (
    <PageWrapper>
      <PageContainer>
        <Title>결제 실패</Title>
        <Subtitle>오류로 인해 결제가 실패하였습니다:</Subtitle>
        <ButtonContainer>
          <Button onClick={handleGoHome} primary>쇼핑몰로 돌아가기</Button>
        </ButtonContainer>
      </PageContainer>
    </PageWrapper>
  );
}

export default FailPage;

const PageWrapper = styled.div`
  display: flex;
  flex-direction: column;
  min-height: 50vh;
  margin-top: 400px;
`;

const PageContainer = styled.div`
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
  text-align: center;
  flex: 1;
`;

const Title = styled.h1`
  font-size: 28px;
  margin-bottom: 10px;
`;

const Subtitle = styled.p`
  font-size: 18px;
  color: #666;
  margin-bottom: 20px;
`;


const ButtonContainer = styled.div`
  display: flex;
  justify-content: center;
  gap: 20px;
`;

const Button = styled.button`
  padding: 10px 20px;
  border: none;
  background-color: ${({ primary }) => (primary ? "#ffa150" : "#ddd")};
  color: ${({ primary }) => (primary ? "#fff" : "#333")};
  font-size: 16px;
  cursor: pointer;
`;

