import React, { useState } from "react";
import magnifyingGlassIcon from "../../static/magnifyingGlass.png";
import "./css/BoardSearchBox.css";
import { SERVER_URL } from "../../config/Constants.js";
import apiClient from "../../token/AxiosConfig";

const BoardSearchBox = ({ setSearchResults }) => {
  const [keyword, setKeyword] = useState("");
  const [page, setPage] = useState(1); // 현재 페이지 번호

  const handleInputChange = (e) => {
    setKeyword(e.target.value);
  };

  const handleSearch = async (event) => {
    event.preventDefault(); // 기본 폼 제출 동작 방지

    try {
      const response = await apiClient.get(`${SERVER_URL}board/search`, {
        params: {
          keyword: keyword, // 검색 키워드 쿼리 파라미터로 전송
          page,
          size: 10,
        },
      });

      if (response && response.data && response.data.dtoList) {
        const { dtoList = [] } = response.data;
        console.log(dtoList);
        console.log(page);
        if (dtoList.length === 0) {
          alert(`${keyword}에 대한 검색결과가 없습니다.`);
        } else {
          setSearchResults(dtoList); // 검색 결과 업데이트
          setPage(response.data.page); // 페이지 상태 업데이트
        }
      } else {
        console.error("응답 데이터가 유효하지 않습니다.");
      }
    } catch (error) {
      console.error("검색 중 오류 발생:", error);
    }
  };

  return (
    <div className="board-search-container flex justify-center relative">
      <form onSubmit={handleSearch} className="board-search-form flex absolute">
        <input
          type="text"
          placeholder="제목으로 검색"
          value={keyword}
          onChange={handleInputChange}
          className="board-search-input"
        />
        <button type="submit" className="board-search-button pointer">
          <img
            src={magnifyingGlassIcon}
            alt="검색"
            className="board-search-icon"
          />
        </button>
      </form>
    </div>
  );
};

export default BoardSearchBox;
