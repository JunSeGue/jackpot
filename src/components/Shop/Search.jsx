import React, { useState } from "react";
import styled from "styled-components";
import apiNoToken from "../../token/AxiosConfig";

const Search = ({ setSearchResults, setName }) => {
  const [query, setQuery] = useState(""); 

  const handleSearch = async () => {
    if (!query.trim()) { 
      alert("검색어를 입력해주세요.");
      return;
    }

    try {
      const response = await apiNoToken.get(`shop/search`, {
        params: { name: query, page: 1, size: 12 },
      });

      if (!response.data || !response.data.dtoList || response.data.dtoList.length === 0) {
        alert(`${query}에 대한 검색결과가 없습니다.`);
        setSearchResults([]); // 검색결과 초기화
      } else {
        setSearchResults(response.data.dtoList || []);
        setName(query); 
      }
    } catch (error) {
      console.error("검색 중 오류 발생:", error);
      alert("검색 중 오류가 발생했습니다. 다시 시도해주세요."); // 오류 알림 추가
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") {
      handleSearch();
    }
  };

  const handleChange = (e) => {
    const value = e.target.value;
    setQuery(value);
  };

  return (
    <StyledWrapper>
      <div className="group">
        <input
          id="name"
          className="input"
          type="search"
          placeholder="Search..."
          value={query}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
        />
        <svg
          onClick={handleSearch}
          viewBox="0 0 24 24"
          aria-hidden="true"
          className="search-icon"
        >
          <g>
            <path d="M21.53 20.47l-3.66-3.66C19.195 15.24 20 13.214 20 11c0-4.97-4.03-9-9-9s-9 4.03-9 9 4.03 9 9 9c2.215 0 4.24-.804 5.808-2.13l3.66 3.66c.147.146.34.22.53.22s.385-.073.53-.22c.295-.293.295-.767.002-1.06zM3.5 11c0-4.135 3.365-7.5 7.5-7.5s7.5 3.365 7.5 7.5-3.365 7.5-7.5 7.5-7.5-3.365-7.5-7.5z" />
          </g>
        </svg>
      </div>
    </StyledWrapper>
  );
};

export default Search;


const StyledWrapper = styled.div`
  position: relative;
  margin-top: 80px;

  .group {
    display: flex;
    align-items: center;
    max-width: 1200px;
    width: 1200px !important ;
    padding: 10px;
    margin: 0 auto;
  }

  .input {
    font-family: "Montserrat", sans-serif;
    width: 100%;
    height: 45px;
    padding-left: 1rem;
    padding-right: 2.5rem;
    box-shadow: 0 0 0 1.5px #2b2c37, 0 0 25px -17px #000;
    border: 0;
    border-radius: 8px;
    background-color: white;
    color: black;
    outline: none;
  }

  .input::placeholder {
    color: black;
  }

  .search-icon {
    position: absolute;
    right: 1rem;
    fill: black;
    width: 1rem;
    height: 1rem;
    cursor: pointer;
  }
`;
