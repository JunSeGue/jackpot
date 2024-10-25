import React, { useState } from "react";
import Search from "../components/Shop/Search";
import SideBar from "../components/Shop/SideBar";
import MainCarousel from "../components/Shop/ShopCarousel";
import Card from "../components/Shop/Card";
import styled from "styled-components";

function ShopPage() {
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [searchResults, setSearchResults] = useState([]); 
  const [name, setName] = useState(""); 

  const handleCategoryChange = (newCategory) => {
    setSelectedCategory(newCategory);
    setSearchResults([]); 
    setName(""); // 검색어도 초기화
  };
  
  return (
    <PageContainer>
      <MainContentWrapper>
        <SearchWrapper>
          <Search setSearchResults={setSearchResults} setName={setName} /> 
        </SearchWrapper>
        <CarouselWrapper>
          <MainCarousel />
        </CarouselWrapper>
        <ContentWrapper>
          <SideBarWrapper>
            <SideBar setSelectedCategory={handleCategoryChange} />
          </SideBarWrapper>
              <Card category={selectedCategory} products={searchResults} name={name} /> 
        </ContentWrapper>
      </MainContentWrapper>
    </PageContainer>
  );
}


export default ShopPage;


const PageContainer = styled.div`
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  overflow-x: hidden;
`;

const MainContentWrapper = styled.div`
  flex: 1;
  display: flex;
  flex-direction: column;
  max-width: 1900px;
  width: 100%;
  align-items: center;
  justify-content: center;
  margin: 0 auto;
`;

const SearchWrapper = styled.div`
  width: 100%;
  padding: 10px 0;
  display: flex;
  justify-content: center;
`;

const CarouselWrapper = styled.div`
  width: 1200px;
  height: auto;
  display: flex;
  justify-content: center;
  margin-bottom: 20px;
`;

const ContentWrapper = styled.div`
  display: flex;
  width: 100%;
  max-width: 1820px;
  padding: 20px;
  justify-content: flex-start;
  align-items: flex-start;
    gap: 40px; /* 사이드바와 카드 사이에 여백 추가 */
   
`;

const SideBarWrapper = styled.div`
  flex: 0 0 250px; /* 사이드바 너비를 고정 */
  margin-right: 20px;
`;
