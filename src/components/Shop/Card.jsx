import React, { useState, useEffect, useCallback } from "react";
import styled from "styled-components";
import { useNavigate, useLocation } from "react-router-dom";
import apiNoToken from "../../token/AxiosConfig";

const Card = ({ name }) => {
  const navigate = useNavigate();
  const location = useLocation();

  const [fetchedProducts, setFetchedProducts] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [sortOrder, setSortOrder] = useState("latest");
  const [isLoading, setIsLoading] = useState(true);
  const [categories] = useState([]); // 카테고리 상태 추가
  const [selectedCategory, setSelectedCategory] = useState(null); // 선택된 카테고리 상태 추가
  const itemsPerPage = 12;

  // URL에서 현재 페이지와 정렬 순서, 선택된 카테고리 가져오기
  useEffect(() => {
    const queryParams = new URLSearchParams(location.search);
    const sortOrderFromUrl = queryParams.get("sortOrder") || "latest";
    const pageFromUrl = parseInt(queryParams.get("page"), 10) || 1;
    const categoryFromUrl = queryParams.get("category");

    setSortOrder(sortOrderFromUrl);
    setCurrentPage(pageFromUrl);
    setSelectedCategory(categoryFromUrl || null);
  }, [location.search]);

  const updateUrlParams = useCallback(
    (newSortOrder, newPage, newCategory) => {
      const queryParams = new URLSearchParams(location.search);
      if (newCategory) {
        queryParams.set("category", newCategory);
      } else {
        queryParams.delete("category");
      }
      queryParams.set("sortOrder", newSortOrder);
      queryParams.set("page", newPage);
      navigate({ search: queryParams.toString() }, { replace: true });
    },
    [navigate, location.search]
  );

  // 상품 목록 가져오기
  const fetchProducts = useCallback(async () => {
    setIsLoading(true);
    try {
      let endpoint;
      const params = { page: currentPage, size: itemsPerPage, sortOrder };

      if (name) {
        // 이름이 있으면 해당 이름으로 검색
        endpoint = `/shop/search`;
        params.name = name;
      } else if (selectedCategory) {
        // 선택된 카테고리가 있으면 해당 카테고리로 검색
        endpoint = `/shop/category/${selectedCategory}`;
      } else {
        // 기본 전체 상품 목록
        endpoint = "/shop/findList";
      }

      const response = await apiNoToken.get(endpoint, { params });
      console.log('총 상품 수:', response.data.total);
      console.log('총 페이지 수:', totalPages);
      console.log('API 요청 파라미터:', params);
      console.log('API 응답 데이터:', response.data);

      console.log("현재 페이지:", currentPage);
      console.log("총 페이지 수:", totalPages);
      console.log("응답에서 받은 total 값:", response.data.total);

      const fetchedProducts = response.data.dtoList || [];
      setFetchedProducts(fetchedProducts);
      setTotalPages(Math.ceil(response.data.total / itemsPerPage));
    } catch (error) {
      console.error("상품 데이터를 가져오는 중 오류 발생:", error);
    } finally {
      setIsLoading(false);
    }
  }, [name, selectedCategory, currentPage, sortOrder, itemsPerPage]);
  
  console.log("상품 개수:", fetchedProducts.length);

  // 데이터를 가져오는 useEffect
  useEffect(() => {
    fetchProducts();
  }, [fetchProducts]);

  // 페이지 변경 처리
  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPage(newPage);
      updateUrlParams(sortOrder, newPage, selectedCategory);
    }
  };

  // 정렬 순서 변경 처리
  const handleSortChange = (newSortOrder) => {
    if (newSortOrder !== sortOrder) {
      setSortOrder(newSortOrder);
      setCurrentPage(1); // 정렬 순서 변경 시 페이지를 1로 초기화
      updateUrlParams(newSortOrder, 1, selectedCategory);
    }
  };

  // 카테고리 변경 처리
  const handleCategoryChange = (category) => {
    setSelectedCategory(category);
    setCurrentPage(1); // 카테고리 변경 시 페이지를 1로 초기화
    updateUrlParams(sortOrder, 1, category);
  };

  // 상품 클릭 시 상세 페이지로 이동
  const handleProductClick = (shopId) => {
    navigate(`/shop/${shopId}`);
  };

  // 로딩 상태일 때
  if (isLoading) {
    return <StyledWrapper></StyledWrapper>;
  }

  // 상품이 없을 때
  if (fetchedProducts.length === 0) {
    alert("해당 이름에 대한 상품이 없습니다.");
    return null;
  }

  return (
    <StyledWrapper>
      <div className="controls">
        {/* 카테고리 선택 버튼 추가 */}
        <div className="category-buttons">
          {categories.map((category) => (
            <button
              key={category.id}
              className={selectedCategory === category.id ? "active" : ""}
              onClick={() => handleCategoryChange(category.id)}
            >
              {category.name}
            </button>
          ))}
        </div>

        <div className="sort-buttons">
          <button
            className={sortOrder === "latest" ? "active" : ""}
            onClick={() => handleSortChange("latest")}
          >
            최신순
          </button>
          <button
            className={sortOrder === "lowToHigh" ? "active" : ""}
            onClick={() => handleSortChange("lowToHigh")}
          >
            낮은 가격순
          </button>
          <button
            className={sortOrder === "highToLow" ? "active" : ""}
            onClick={() => handleSortChange("highToLow")}
          >
            높은 가격순
          </button>
        </div>
      </div>

      <div className="products-container">
        {fetchedProducts.map((product) => (
          <div
            className="card"
            key={product.shopId}
            onClick={() => handleProductClick(product.shopId)}
          >
            <div className="image-container">
              <img
                src={product.mainImage || "기본이미지경로"}
                alt={product.name}
              />
            </div>
            <div className="card-content">
              <h3>{product.name}</h3>
              <p>
                {product.price
                  ? product.price.toLocaleString()
                  : "가격 정보 없음"}
                원
              </p>
            </div>
          </div>
        ))}
      </div>

      <PaginationWrapper>
        <button
          onClick={() => handlePageChange(currentPage - 1)}
          disabled={currentPage === 1}
        >
          이전
        </button>
        <span>
          {currentPage} / {totalPages}
        </span>
        <button
          onClick={() => handlePageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
        >
          다음
        </button>
      </PaginationWrapper>
    </StyledWrapper>
  );
};

export default Card;

// 스타일 수정
const PaginationWrapper = styled.div`
  display: flex;
  justify-content: center; /* 중앙 정렬 */
  align-items: center;
  gap: 10px;
  margin-top: 20px;
  width: 100%; /* 부모 요소의 너비를 가득 채움 */

  button {
    background-color: #ff7600;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    margin: 0 1rem;
    cursor: pointer;
    transition: background-color 0.3s;
    border-radius: 0.5rem;

    &:hover {
      background-color: #d64229;
    }

    &:disabled {
      background-color: gray;
      cursor: not-allowed;
    }
  }

  .active {
    background-color: #0056b3;
  }
`;

const StyledWrapper = styled.div`
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 1200px;
  box-sizing: border-box;
  justify-content: center;
  align-items: center;
  position: relative;
  min-height: 300px; /* 필요한 최소 높이 지정 */

  .controls {
    display: flex;
    justify-content: flex-start;
      width: 100%; /* 부모 요소의 전체 너비를 차지 */

    margin-bottom: 20px;
  }

  .sort-buttons {
    display: flex;
    gap: 10px;
    button {
      padding: 5px 10px;
      font-size: 12px;
      cursor: pointer;
    }
  }

  .products-container {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 45px;
    width: 100%;
    max-width: 1200px;
    margin-bottom: 20px; /* 카드 리스트 하단 여백 추가 */

    @media (max-width: 1200px) {
      grid-template-columns: repeat(3, 1fr);
    }

    @media (max-width: 768px) {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  .no-products {
    display: flex;
    justify-content: center;
    align-items: center;
    text-align: center;
    font-size: 18px;
    color: #666;
    height: 100%;
    min-height: 600px; /* 최소 높이로 세로 가운데 정렬 */
  }

  .card {
    background-color: #f9f9f9;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    width: 266px;
    height: 355px;
    align-items: center;
    transition: transform 0.2s;
    cursor: pointer;
  }

  .card:hover {
    transform: scale(1.05);
  }

  .image-container {
    width: 100%;
    height: 250px;
    background-color: #ddd;
  }

  .image-container img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  .card-content {
    padding: 10px;
    text-align: center;
  }

  .card-content h3 {
    margin: 10px 0;
    font-size: 16px;
  }

  .card-content p {
    margin: 5px 0;
    color: #555;
  }

  .price {
    font-size: 14px;
    font-weight: bold;
    color: #333;
  }
`;