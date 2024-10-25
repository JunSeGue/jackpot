import React, { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import styled from "styled-components";
import apiClient from "../../token/AxiosConfig";

export function SuccessPage() {
  const [searchParams] = useSearchParams();
  const [paymentInfo, setPaymentInfo] = useState(null);
  const navigate = useNavigate();
  const [isConfirming, setIsConfirming] = useState(true);

  const paymentData = JSON.parse(sessionStorage.getItem("paymentData")) || {};
  console.log("sessionStorage에서 가져온 결제 데이터:", paymentData);

  const {
    memberID,
    customerName = "",
    customerMobilePhone = "",
    userAddress = "",
    deliveryFee = 3000,
    orderId,
    shopId = "",
    orderName: name,
    isFunding = false, 
    name: dogName = "", 
    dogId = "", 
    productNames = [] 
  } = paymentData;

  useEffect(() => {
    if (!orderId) {
      console.log("orderId가 없습니다. 결제 정보가 유실되었습니다.");
      navigate(`/fail?message=결제 정보가 유실되었습니다.`);
      return;
    }

    // 공통 데이터 생성
    const commonRequestData = {
      orderId: searchParams.get("orderId") || orderId,
      amount: searchParams.get("amount"),
      paymentKey: searchParams.get("paymentKey"),
      isFunding, 
    };

    // 펀딩일 경우의 데이터
    const fundingData = isFunding ? {
      orderName: dogName,
      name, 
      dogId, 
    } : {};

    // 상품일 경우의 데이터
    const productData = !isFunding
      ? {
          shopId, 
          orderName: name, 
          memberID,
          name: customerName,
          phone: customerMobilePhone,
          address: userAddress,
          productNames: productNames.map(item => ({
            shopName: item.shopName || item.name,
            quantity: item.quantity || 1,
            shopId: item.shopId,
            totalProductPrice: (item.productPrice || 0) * (item.quantity || 1), 
          }))
        }
      : {};

    // 최종 요청 데이터 생성
    const requestData = {
      ...commonRequestData,
      ...fundingData,
      ...productData,
    };

    console.log("전송할 requestData:", requestData);


    async function confirm() {
      try {
        console.log("전송할 requestData:", requestData); 

        const response = await apiClient.post("/api/confirm", requestData, {
          headers: {
            Authorization: "Basic " + btoa("test_gsk_docs_OaPz8L5KdmQXkzRz3y47BMw6:"),
            "Content-Type": "application/json",
          },
        });
        console.log("백엔드 응답:", response.data);

        if (response.status !== 200) {
          navigate(`/fail?message=${response.data.message}&code=${response.data.code}`);
          return;
        }

        setPaymentInfo(response.data);
        setIsConfirming(false);

        if (isFunding) {
          navigate(`/dog/${dogId}`, {
            state: { successMessage: "펀딩에 성공했습니다!" },
          });
        }
      } catch (error) {
        console.error("결제 확인 중 오류 발생:", error);
        navigate(`/fail?message=결제 확인 중 오류가 발생했습니다.`);
      }
    }

      confirm();
  }, [searchParams, navigate, orderId, isFunding]);

  if (isConfirming) {
    return <div>결제 확인 중...</div>;
  }

  if (!paymentInfo) {
    return <div>결제 정보를 불러올 수 없습니다.</div>;
  }

  const { totalAmount } = paymentInfo; 

  return !isFunding ? (
    <PageContainer>
      <Title>주문완료</Title>
      <Subtitle>주문이 완료되었습니다. 감사합니다!</Subtitle>
      <Section>
        <SectionTitle>상품배송 정보</SectionTitle>
        {productNames.map((product, index) => (
            <InfoRow key={index}>
              <InfoLabel>{product.name} ({product.quantity}개)</InfoLabel>
            </InfoRow>
        ))}
      </Section>
      <InfoContainer>
        <LeftColumn>
          <SectionTitle>받는사람 정보</SectionTitle>
          <InfoRow>
            <InfoLabel>받는사람</InfoLabel>
            <InfoValue>{customerName} / {customerMobilePhone}</InfoValue>
          </InfoRow>
          <InfoRow>
            <InfoLabel>받는주소</InfoLabel>
            <InfoValue>{userAddress}</InfoValue>
          </InfoRow>
        </LeftColumn>
        <RightColumn>
          <SectionTitle>결제 정보</SectionTitle>
          <InfoRow>
            <InfoLabel>주문금액</InfoLabel>
            <InfoValue>{(totalAmount - deliveryFee).toLocaleString()}원</InfoValue>
          </InfoRow>
          <InfoRow>
            <InfoLabel>배송비</InfoLabel>
            <InfoValue>{deliveryFee.toLocaleString()} 원</InfoValue>
          </InfoRow>
          <TotalRow>
            <TotalLabel>총 결제금액</TotalLabel>
            <TotalValue>{totalAmount.toLocaleString()} 원</TotalValue>
          </TotalRow>
        </RightColumn>
      </InfoContainer>
      <ButtonContainer>
        <Button primary={true} onClick={() => navigate("/shop")}>쇼핑 계속하기</Button>
      </ButtonContainer>
    </PageContainer>
  ) : null; 
}

export default SuccessPage;

const PageContainer = styled.div`
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
  background-color: #f9f9f9;
  margin-top: 100px;
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

const Section = styled.div`
  margin-bottom: 20px;
`;

const SectionTitle = styled.h2`
  font-size: 20px;
  border-bottom: 1px solid #ddd;
  padding-bottom: 10px;
`;

const InfoRow = styled.div`
  display: flex;
  justify-content: space-between;
  padding: 10px 0;
  &:nth-child(odd) {
    background-color: #f1f1f1;
  }
`;

const InfoLabel = styled.span`
  font-weight: bold;
`;

const InfoValue = styled.span`
  color: #333;
`;

const InfoContainer = styled.div`
  display: flex;
  justify-content: space-between;
  margin-top: 20px;
`;

const LeftColumn = styled.div`
  width: 48%;
`;

const RightColumn = styled.div`
  width: 48%;
`;

const TotalRow = styled(InfoRow)`
  font-size: 18px;
  font-weight: bold;
  border-top: 1px solid #ddd;
  padding-top: 10px;
`;

const TotalLabel = styled.span`
  font-weight: bold;
`;

const TotalValue = styled.span`
  color: #f00;
`;

const ButtonContainer = styled.div`
  display: flex;
  justify-content: flex-end;
  margin-top: 30px;
`;

const Button = styled.button`
  padding: 10px 20px;
  border: none;
  background-color: #ffa150;
  color: #fff;
  font-size: 16px;
  cursor: pointer;
  border-radius: 5px;
`;
