// ShopDetailPage.jsx
import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import NavBar from "../components/Main/NavBar";
import Sidebar from "../components/Shop/SideBar";
import ProductDetail from "../components/Shop/ShopDetail/ProductDetail";
import ProductInfo from "../components/Shop/ShopDetail/ProductInfo";
import styled from "styled-components";

const ShopDetailPage = () => {
  const { shopId } = useParams();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(false);
  }, [shopId]);

  if (loading) {
    return null;
  }

  return (
    <PageContainer>
      <NavBar />
      <ContentWrapper>
        <SidebarContainer>
          <Sidebar />
        </SidebarContainer>
        <DetailContentWrapper>
          <ProductInfo shopId={shopId} />
          <ProductDetail shopId={shopId} />
        </DetailContentWrapper>
      </ContentWrapper>
    </PageContainer>
  );
};

export default ShopDetailPage;

// 스타일 정의
const PageContainer = styled.div`
  display: flex;
  flex-direction: column;
  width: 100%;
  min-height: 100vh;
`;

const ContentWrapper = styled.div`
  display: flex;
  width: 100%;
  max-width: 1800px;
  margin: 0 auto;
  padding: 20px;
  gap: 40px; /* 사이드바와 메인 콘텐츠 사이의 간격 */
  margin-top: 200px; /* 기존 margin-top 제거 */
  min-height: 1200px; /* 최소 높이값 지정 */
`;

const SidebarContainer = styled.div`
  flex: 0 0 250px; /* 사이드바의 고정 너비 설정 */
`;

const DetailContentWrapper = styled.div`
  flex-grow: 1;
  display: flex;
  flex-direction: column;
  gap: 20px;
  width: 100%;
  min-height: 600px;

`;
