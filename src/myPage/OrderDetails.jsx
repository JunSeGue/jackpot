import React from "react";
import styled from "styled-components";

const OrderDetails = ({ orderData }) => {
  // 받는 사람 정보는 첫 번째 아이템에서 가져옵니다.
  const receiver = orderData[0];
  const deliveryFee = 3000; // 고정 배송비 설정
  const totalProductPrice = orderData.reduce((total, product) => total + product.shopPrice * product.quantity, 0);
  const totalPrice = totalProductPrice + deliveryFee;


  

  return (
    <DetailsContainer>
      <h2>주문 상세</h2>
      <Section>
        <SectionTitle>받는사람 정보</SectionTitle>
        <ReceiverInfo>
          <InfoRow>
            <InfoTitle>받는사람</InfoTitle>
            <InfoText>{receiver.name}</InfoText>
          </InfoRow>
          <InfoRow>
            <InfoTitle>연락처</InfoTitle>
            <InfoText>{receiver.phone}</InfoText>
          </InfoRow>
          <InfoRow>
            <InfoTitle>받는주소</InfoTitle>
            <InfoText>{receiver.address}</InfoText>
          </InfoRow>
        </ReceiverInfo>
      </Section>

      <Section>
        <SectionTitle>결제 정보</SectionTitle>
        <PaymentTable>
          <TableRow>
            <TableCell>총 상품가격</TableCell>
            <TableCell>{totalProductPrice.toLocaleString()} 원</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>배송비</TableCell>
            <TableCell>{deliveryFee.toLocaleString()} 원</TableCell>
          </TableRow>
          <TableRow>
            <TableCell style={{ fontWeight: "bold" }}>총 결제금액</TableCell>
            <TableCell style={{ fontWeight: "bold" }}>{totalPrice.toLocaleString()} 원</TableCell>
          </TableRow>
        </PaymentTable>
      </Section>
    </DetailsContainer>
  );
};

const DetailsContainer = styled.div`
  padding: 20px;
  background: #fff;
  border-radius: 8px;
  margin-top: 20px;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
`;

const Section = styled.div`
  margin-bottom: 30px;
`;

const SectionTitle = styled.h3`
  text-align: left;
  font-size: 18px;
  font-weight: bold;
  margin-bottom: 15px;
`;

const ReceiverInfo = styled.div`
  border-top: 2px solid #000;
  padding: 15px 0;
`;

const InfoRow = styled.div`
  display: flex;
  justify-content: space-between; /* 왼쪽과 오른쪽 정렬을 위해 설정 */
  padding: 8px 0;
`;

const InfoTitle = styled.div`
  font-weight: bold;
  width: 120px;
  text-align: left;
`;

const InfoText = styled.div`
  flex: 1;
  text-align: right; /* 오른쪽 정렬 */
`;

const PaymentTable = styled.div`
  border-top: 2px solid #000;
  margin-top: 15px;
  padding-top: 10px;
`;

const TableRow = styled.div`
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
`;

const TableCell = styled.div`
  flex: 1;
  text-align: right;
  font-size: 14px;
  &:first-child {
    text-align: left;
  }
`;

export default OrderDetails;
