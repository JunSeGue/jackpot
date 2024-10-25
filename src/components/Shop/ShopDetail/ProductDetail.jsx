import React, { useEffect, useState } from "react";
import styled from "styled-components";
import apiNoToken from "../../../token/AxiosConfig"; // API 클라이언트 임포트

const ProductDetail = ({ shopId }) => {
  const [product, setProductDetails] = useState({
    
    detail: "",
    detailImages: [],
  });
  console.log("Received shopId: ", shopId);

  useEffect(() => {

    const fetchProductDetails = async () => {
      try {
        const response = await apiNoToken.get(`/shop/findOne/${shopId}`);
        const data = response.data;

        setProductDetails({
          detail: data.detail || "",
          detailImages: [
            data.detailImage1,
            data.detailImage2,
            data.detailImage3,
            data.detailImage4,
          ],
        });
      } catch (error) {
        console.error("상품 세부 정보를 불러오는 중 오류 발생:", error);
      }
    };

    fetchProductDetails();
  }, [shopId]);

  return (
    <StyledContainer>
      <div className="box-wrapper">
        <h2 className="title">상품 정보</h2>
      </div>
      <div className="history-section">
        <div className="pictures-section">
          {product.detailImages.map((image, index) => (
            <div key={index}>
              <img src={image} alt={`detail-image-${index}`} />
            </div>
          ))}
        </div>

        <div className="dog-info-section">
          <h3>상세 설명</h3>
          <p>{product.detail}</p>
        </div>
      </div>
    </StyledContainer>
  );
};

export default ProductDetail;

const StyledContainer = styled.div`
  margin-top: 20px;

  .box-wrapper {
    border-top: 1px solid black;
    border-bottom: 1px solid black;
    padding: 10px 0;
  }

  .title {
    text-align: left;
    margin: 0;
    padding: 0;
  }

  .history-section {
    margin: 20px 0;
    width: 100%;
    height: 400px;
    display: flex;
    gap: 5%;
  }

  .pictures-section {
    display: grid;
    grid-template-columns: 1fr 1fr;
    column-gap: 30px;
    padding: 20px;
  }

  .pictures-section img {
    width: 100%;
    height: 150px;
    object-fit: cover;
    box-shadow: 0 0 10px 5px #666;
  }

  .pictures-section img:nth-child(even) {
    transform: translateY(70px); /* 짝수 번째 이미지 아래로 이동 */
  }

  .dog-info-section {
    flex: 1;
    padding: 0 20px;
    text-align: left;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }
`;
