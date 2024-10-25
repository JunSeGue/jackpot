import React, { useEffect, useState } from "react";
import styled from "styled-components";
import apiClient from "../token/AxiosConfig";
import Grid from "@mui/material/Grid2";
import logo from "../static/newLogoverticalOrange.png";
import Button from "@mui/material/Button";
import { useNavigate } from "react-router-dom"; // useNavigate 임포트 수정

const OrderList = () => {
  const [orderItems, setOrderItems] = useState([]); // 장바구니 -> 주문 내역
  const navigate = useNavigate();

  const fetchOrderItems = async () => {
    try {
      const response = await apiClient.get("order/findAll"); // 주문 내역에 맞는 엔드포인트
      setOrderItems(response.data);
    } catch (error) {
      console.error("Error fetching order items:", error);
    }
  };

  useEffect(() => {
    fetchOrderItems();
  }, []);

  return (
    <div className="container">
      <Grid
        container
        style={{ marginTop: "50px", justifyContent: "flex-start" }}
      >
        <Grid size={{ xs: 6, md: 7 }} style={{ marginLeft: "200px" }}>
          <StyledWrapper>
            <div className="master-container">
              {orderItems.map((item) => (
                <div className="card order" key={item.orderId}> {/* cart -> order */}
                  <label className="title">주문 내역</label>
                  <div className="products">
                    <div className="product">
                      <img
                        src={logo}
                        alt="상품 이미지 대체 로고"
                        style={{ height: "80px", width: "80px" }}
                      ></img>
                      <div>
                        <span>{item.shopName}</span>
                        <p>{item.shopId}번 상품</p>
                        <p>{item.shopPrice}원</p>
                      </div>
                      <label className="price small">
                        {item.shopPrice.toLocaleString()}원
                      </label>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </StyledWrapper>
        </Grid>
      </Grid>
    </div>
  );
};

export default OrderList;

const StyledWrapper = styled.div`
  .master-container {
    display: flex;
    justify-content: center;
    align-items: center;
    flex-direction: column;
  }

  .card {
    width: 50%;
    height: auto;
    margin-bottom: 20px;
    background: #ffffff;
    box-shadow: 0px 187px 75px rgba(0, 0, 0, 0.01),
      0px 105px 63px rgba(0, 0, 0, 0.05), 0px 47px 47px rgba(0, 0, 0, 0.09),
      0px 12px 26px rgba(0, 0, 0, 0.1), 0px 0px 0px rgba(0, 0, 0, 0.1);
  }

  .title {
    width: 100%;
    height: 40px;
    position: relative;
    display: flex;
    align-items: center;
    padding-left: 20px;
    border-bottom: 1px solid #efeff3;
    font-weight: 700;
    font-size: 20px;
    color: #63656b;
  }

  .order {
    border-radius: 19px 19px 7px 7px;
  }

  .order .products {
    display: flex;
    flex-direction: column;
    padding: 10px;
  }

  .order .products .product {
    display: grid;
    grid-template-columns: 60px 1fr 80px 1fr;
    gap: 10px;
  }

  .order .products .product span {
    font-size: 13px;
    font-weight: 600;
    color: #47484b;
    margin-bottom: 8px;
    display: block;
  }

  .order .products .product p {
    font-size: 11px;
    font-weight: 600;
    color: #7a7c81;
  }

  .card .small {
    font-size: 15px;
    margin: 0 0 auto auto;
  }
`;
