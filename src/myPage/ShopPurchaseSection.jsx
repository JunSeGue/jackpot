import React, { useEffect, useState } from "react";
import styled from "styled-components";
import apiClient from "../token/AxiosConfig";
import OrderDetails from "./OrderDetails";

const PurchaseHistorySection = ({ showAll }) => {
  const [shopData, setShopData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedOrder, setSelectedOrder] = useState(null);

  useEffect(() => {
    const fetchOrderData = async () => {
      try {
        const response = await apiClient.get("/order/findAll");

        // ID 기준으로 내림차순 정렬하여 최신 항목이 위로 오도록 처리
        const sortedData = response.data.sort((a, b) => b.id - a.id);

        setShopData(sortedData);
      } catch (error) {
        console.error("Failed to fetch order data:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchOrderData();
  }, []);

  const groupedOrders = shopData.reduce((acc, item) => {
    const orderId = item.orderId;
    if (!acc[orderId]) {
      acc[orderId] = [];
    }
    acc[orderId].push(item);
    return acc;
  }, {});

  const displayedOrderKeys = showAll
    ? Object.keys(groupedOrders)
    : Object.keys(groupedOrders).slice(0, 3);

  if (loading) {
    return <Loading>Loading...</Loading>;
  }

  const selectedOrderData = selectedOrder ? groupedOrders[selectedOrder] : null;

  const handleCancelProduct = (orderId, shopId) => {
    const ordersDTO = {
      orderId,
      deliveryState: 4,
      shopId,
    };

    apiClient.post(`/order/edit`, ordersDTO)
      .then(() => {
        alert("해당 상품이 취소되었습니다.");
        setShopData((prevData) =>
          prevData.map((item) =>
            item.orderId === orderId && item.shopId === shopId
              ? { ...item, deliveryState: 4 }
              : item
          )
        );
      })
      .catch((error) => {
        console.error("상품 취소 실패:", error);
      });
  };

  return (
    <Container>
      <Title>구매내역</Title>
      {shopData.length ? (
        <>
          {selectedOrder ? (
            <OrderGroup
              key={selectedOrder}
              orderId={selectedOrder}
              orderDate={groupedOrders[selectedOrder]?.[0]?.orderDate || "알 수 없음"}
              shopData={groupedOrders[selectedOrder]}
              setSelectedOrder={setSelectedOrder}
              handleCancelProduct={handleCancelProduct}
            />
          ) : (
            displayedOrderKeys.map((orderId) => (
              <OrderGroup
                key={orderId}
                orderId={orderId}
                orderDate={groupedOrders[orderId]?.[0]?.orderDate || "알 수 없음"}
                shopData={groupedOrders[orderId]}
                setSelectedOrder={setSelectedOrder}
                handleCancelProduct={handleCancelProduct}
              />
            ))
          )}
        </>
      ) : (
        <EmptyContent>구매 내역이 없습니다.</EmptyContent>
      )}
      {selectedOrderData && <OrderDetails orderData={selectedOrderData} />}
    </Container>
  );
};

const OrderGroup = ({ orderId, created_at, shopData, setSelectedOrder, handleCancelProduct }) => {
  const handleViewDetails = () => {
    setSelectedOrder(orderId);
  };

  return (
    <OrderGroupContainer>
      <OrderDateHeader>주문</OrderDateHeader>
      <OrderGroupActions>
        <ViewDetailsButton onClick={handleViewDetails}>상세보기</ViewDetailsButton>
      </OrderGroupActions>
      {shopData.map((item) => (
        <PurchaseHistory
          key={item.id}
          shopData={item}
          handleCancelProduct={handleCancelProduct}
          orderId={orderId}
        />
      ))}
    </OrderGroupContainer>
  );
};

const PurchaseHistory = ({ shopData, handleCancelProduct, orderId }) => {
  const stateInfo = (() => {
    switch (shopData.deliveryState) {
      case 0:
        return { text: "배송 준비 중", color: "black" };
      case 1:
        return { text: "배송 중", color: "orange" };
      case 2:
        return { text: "배송 완료", color: "green" };
      case 4:
        return { text: "구매 취소", color: "red" };
      default:
        return { text: "서비스 에러", color: "red" };
    }
  })();

  const isCanceled = shopData.deliveryState === 4;

  return (
    <StyledPurchaseSection $statecolor={stateInfo.color}>
      <div className="section-left">
        <h5 className="status">{stateInfo.text}</h5>
        <img
          src={shopData.imageUrl || "https://via.placeholder.com/64"}
          className="thumbnail"
          alt="품목"
        />
        <div className="product-section">
          <p className="productTitle">{shopData.name}</p>
          <span className="productPrice">{shopData.totalPrice}원</span>
          <span className="quantity">x {shopData.quantity}개</span>
        </div>
        {!isCanceled && (
          <CancelButton onClick={() => handleCancelProduct(orderId, shopData.shopId)}>
            구매 취소
          </CancelButton>
        )}
      </div>
    </StyledPurchaseSection>
  );
};

const Container = styled.div`
  padding: 20px;
`;

const Title = styled.h4`
  text-align: left;
  font-size: 1.5rem;
  margin-bottom: 20px;
`;

const OrderGroupContainer = styled.div`
  position: relative;
  margin-bottom: 30px;
  padding: 15px;
  background-color: #fff;
  border: 1px solid #ddd;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
`;

const OrderDateHeader = styled.div`
  font-size: 1.2rem;
  font-weight: bold;
  margin-bottom: 10px;
  color: #333;
`;

const OrderGroupActions = styled.div`
  display: flex;
  justify-content: flex-end;
  gap: 10px;
`;

const ViewDetailsButton = styled.button`
  padding: 8px 16px;
  background-color: #f0f0f0;
  border: none;
  cursor: pointer;
  transition: background-color 0.2s;
  border-radius: 4px;
  text-align: center;

  &:hover {
    background-color: #ddd;
  }
`;

const CancelButton = styled(ViewDetailsButton)`
  background-color: #ff6b6b;
  color: white;

  &:hover {
    background-color: #d9534f;
  }
`;

const EmptyContent = styled.div`
  text-align: center;
  color: #666;
  font-size: 1.2rem;
  margin-top: 20px;
`;

const Loading = styled.div`
  text-align: center;
  font-size: 1.2rem;
  margin-top: 20px;
`;

const StyledPurchaseSection = styled.div`
  .section-left {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    height: fit-content;
    text-align: left;
    padding: 20px;
    margin-bottom: 20px;
    border: 1px solid #ddd;
    border-radius: 8px;
    background: #fff;
  }

  .status {
    width: 100%;
    font-size: 1.2rem;
    color: ${(props) => props.$statecolor};
    margin-bottom: 10px;
  }

  .thumbnail {
    width: 64px;
    height: 64px;
    margin-right: 20px;
  }

  .product-section {
    display: flex;
    flex-direction: column;
    flex-grow: 1;
    margin-left: 20px;
  }

  .productTitle {
    font-size: 1rem;
    font-weight: bold;
    margin-bottom: 5px;
  }

  .productPrice,
  .quantity {
    font-size: 0.9rem;
    color: #666;
  }
`;

export default PurchaseHistorySection;
