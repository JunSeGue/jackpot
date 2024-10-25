import React, { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import styled from "styled-components";
import { loadTossPayments } from "@tosspayments/tosspayments-sdk";
import apiClient from "../../token/AxiosConfig";

const clientKey = "test_gck_docs_Ovk5rk1EwkEbP0W43n07xlzm";
const customerKey = "e6Bp3EiNGF0nTmXJ05nvg";

function CheckoutPage() {
  const location = useLocation();
  const {
    productNames = [], // 상품 배열 정보
    totalAmount = 0,
    isFunding = false,
    name, // 강아지 이름
    dogId = null, 
  } = location.state || {};

  // 상품 개수 계산
  const quantity = Array.isArray(productNames)
    ? productNames.reduce((acc, item) => acc + (item.quantity || 1), 0)
    : productNames.quantity || 1;

  const amount = totalAmount + (isFunding ? 0 : 3000);
  const [ready, setReady] = useState(false);
  const [widgets, setWidgets] = useState(null);
  const [user, setUser] = useState({});
  const [isEditingAddress, setIsEditingAddress] = useState(false);

  // 사용자 정보 API 호출
  useEffect(() => {
    const fetchUserInfo = async () => {
      try {
        const response = await apiClient.get("/member/myPage", {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        });
        setUser(response.data);
      } catch (error) {
        console.error("Error fetching user info:", error);
      }
    };
    fetchUserInfo();
  }, []);

  useEffect(() => {
    async function fetchPaymentWidgets() {
      const tossPayments = await loadTossPayments(clientKey);
      const widgets = tossPayments.widgets({ customerKey });
      setWidgets(widgets);
    }
    fetchPaymentWidgets();
  }, []);

  useEffect(() => {
    async function renderPaymentWidgets() {
      if (!widgets) return;

      await widgets.setAmount({
        currency: "KRW",
        value: parseInt(amount, 10),
      });

      await Promise.all([
        widgets.renderPaymentMethods({
          selector: "#payment-method",
          variantKey: "DEFAULT",
        }),
        widgets.renderAgreement({
          selector: "#agreement",
          variantKey: "AGREEMENT",
        }),
      ]);

      setReady(true);
    }
    renderPaymentWidgets();
  }, [widgets, amount]);

  const handlePayment = async () => {
    const paymentAmount = parseInt(amount, 10);
    const orderId = `order_${Date.now()}`;
  
    if (!ready) {
      alert("결제 준비가 완료되지 않았습니다.");
      return;
    }
  
    try {
      
      let orderName = "";
  
      if (isFunding) {
        orderName = name;
      } else {
        if (Array.isArray(productNames) && productNames.length > 0) {
          orderName = productNames.map((item) => item.shopName || item.name).join(", ");
        } else if (productNames && typeof productNames === "object") {
          orderName = productNames.shopName || productNames.name || "";
        }
      }

      const updatedProductNames = productNames.map(item => ({
        ...item,
        totalProductPrice: (item.productPrice || 0) * (item.quantity || 1), 
      }));

      const paymentData = isFunding
        ? {
            orderId,
            name,
            orderName,
            dogId,
            memberID: user.memberID,
            customerName: user.name,
            customerMobilePhone: user.phone,
            amount: paymentAmount,
            isFunding: true,
          }
        : {
            orderId,
            orderName,
            productNames: updatedProductNames, 
            quantity,
            memberID: user.memberID,
            customerName: user.name,
            customerMobilePhone: user.phone,
            userAddress: user.address || "주소 정보 없음",
            deliveryFee: 3000,
            amount: paymentAmount,
            isFunding: false,
          };

      console.log("결제 요청 데이터:", paymentData);

      sessionStorage.setItem("paymentData", JSON.stringify(paymentData));

      await widgets.requestPayment({
        orderId,
        orderName,
        successUrl: `${window.location.origin}/success?orderId=${orderId}&amount=${paymentAmount}&name=${orderName}`,
        failUrl: `${window.location.origin}/fail`,
        customerEmail: user.email,
        customerName: user.name,
        customerMobilePhone: user.phone,
      });
    } catch (error) {
      console.error("결제 요청 중 오류 발생:", error);
      alert("결제 요청 중 오류가 발생했습니다. 다시 시도해 주세요.");
    }
  };
  
  // 주소 수정 처리
  const handleAddressEdit = () => {
    setIsEditingAddress(true);
  };

  const handleAddressSave = () => {
    setIsEditingAddress(false);
  };

  const handleAddressChange = (e) => {
    const newAddress = e.target.value;
    setUser((prevUser) => ({ ...prevUser, address: newAddress }));
  };

  return (
    <PageContainer>
      <Header>
        <Logo>로고</Logo>
      </Header>
      <Divider />

      <Section>
        <SectionTitle>구매자 정보</SectionTitle>
        <InfoBox>
          <InfoRow>
            <Label>이름</Label>
            <Value>{user.name || "정보 없음"}</Value>
          </InfoRow>
          <InfoRow>
            <Label>이메일</Label>
            <Value>{user.email || "정보 없음"}</Value>
          </InfoRow>
          <InfoRow>
            <Label>휴대폰 번호</Label>
            <Value>{user.phone || "정보 없음"}</Value>
          </InfoRow>
        </InfoBox>
      </Section>

      <Divider />

      {!isFunding && (
        <Section>
          <FlexRow>
            <SectionTitle>받는 사람 정보</SectionTitle>
            {isEditingAddress ? (
              <SaveAddressButton onClick={handleAddressSave}>저장</SaveAddressButton>
            ) : (
              <EditAddressButton onClick={handleAddressEdit}>수정</EditAddressButton>
            )}
          </FlexRow>
          {isEditingAddress ? (
            <Input
              type="text"
              value={user.address || ""}
              onChange={handleAddressChange}
              placeholder="주소를 수정하세요"
            />
          ) : (
            <MessageBox>{user.address || "주소 정보가 없습니다."}</MessageBox>
          )}
        </Section>
      )}

      <Divider />

      <Section>
        <SectionTitle>{isFunding ? "강아지 정보" : "상품 정보"}</SectionTitle>
        {Array.isArray(productNames) && productNames.length > 0 ? (
          productNames.map((item, index) => (
            <ProductInfoBox key={index}>
              <ProductRow>
                <Label>상품명</Label>
                <Value>{item.shopName || item.name || "상품명 불러오기 실패"}</Value>
              </ProductRow>
              <ProductRow>
                <Label>수량</Label>
                <Value>{item.quantity || 1}개</Value>
              </ProductRow>
            </ProductInfoBox>
          ))
        ) : (
          <ProductInfoBox>
            <ProductRow>
              <Label>{isFunding ? "강아지 이름" : "상품명"}</Label>
              <Value>{name || "상품명 불러오기 실패"}</Value>
            </ProductRow>
            <ProductRow>
              <Label>{isFunding ? "후원" : "수량"}</Label>
              <Value>{quantity || 1}개</Value>
            </ProductRow>
          </ProductInfoBox>
        )}
      </Section>

      <Divider />

      <Section>
        <SectionTitle>결제 정보</SectionTitle>
        <InfoBox>
          {isFunding ? (
            <InfoRow>
              <Label>총 결제 금액</Label>
              <Value>{amount.toLocaleString()}원</Value>
            </InfoRow>
          ) : (
            <>
              <InfoRow>
                <Label>총 상품 가격</Label>
                <Value>
                  {totalAmount ? `${totalAmount.toLocaleString()}원` : "가격 정보 없음"}
                </Value>
              </InfoRow>
              <InfoRow>
                <Label>배송비</Label>
                <Value>3,000원</Value>
              </InfoRow>
              <TotalRow>
                <Label>총 결제 금액</Label>
                <Value>{amount.toLocaleString()}원</Value>
              </TotalRow>
            </>
          )}
        </InfoBox>
      </Section>

      <Divider />

      <PaymentSection>
        <MessageBox>
          현재는 <strong>토스, 카카오, 카드 결제</strong>만 가능합니다.
        </MessageBox>
        <div id="payment-method" />
        <div id="agreement" />
        <PayButton onClick={handlePayment} disabled={!ready}>
          결제하기
        </PayButton>
      </PaymentSection>
    </PageContainer>
  );
}

export default CheckoutPage;

const PageContainer = styled.div`
  width: 40%;
  margin: 0 auto;
  padding: 20px;
  margin-top: 100px;
  background-color: #f0f0f0;
`;

const Header = styled.div`
  display: flex;
  justify-content: space-between;
`;

const Logo = styled.h1`
  font-size: 24px;
`;

const Divider = styled.hr`
  border: 1px solid #ddd;
  margin: 20px 0;
`;

const Section = styled.div`
  margin-bottom: 20px;
`;

const SectionTitle = styled.h2`
  font-size: 20px;
  margin-bottom: 10px;
`;

const InfoBox = styled.div`
  border: 1px solid #ddd;
  padding: 20px;
`;

const InfoRow = styled.div`
  display: flex;
  justify-content: space-between;
  margin-bottom: 10px;
`;

const Label = styled.span`
  font-weight: bold;
`;

const Value = styled.span``;

const ProductInfoBox = styled.div`
  border: 1px solid #ddd;
  padding: 20px;
  margin-bottom: 20px;
`;

const ProductRow = styled.div`
  display: flex;
  justify-content: space-between;
`;

const TotalRow = styled(InfoRow)`
  font-size: 18px;
  font-weight: bold;
`;

const PaymentSection = styled.div`
  margin-top: 20px;
`;

const PayButton = styled.button`
  width: 100%;
  background-color: #ffa150;
  color: white;
  padding: 15px;
  border-radius: 8px;
  border: none;
  cursor: pointer;
`;

const FlexRow = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
`;

const EditAddressButton = styled.button`
  background-color: #ffa150;
  color: white;
  border: none;
  padding: 10px;
  border-radius: 5px;
  cursor: pointer;
`;

const SaveAddressButton = styled.button`
  background-color: #ffa150;
  color: white;
  border: none;
  padding: 10px;
  border-radius: 5px;
  cursor: pointer;
`;

const Input = styled.input`
  width: 100%;
  padding: 10px;
  margin-bottom: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
`;

const MessageBox = styled.div`
  border: 1px solid #ddd;
  padding: 10px;
  border-radius: 5px;
  text-align: center;
  background-color: #f9f9f9;
  margin-bottom: 10px;
  font-size: 14px;
  color: #333;
  font-weight: bold;
  strong {
    color: #28a745;
  }
`;