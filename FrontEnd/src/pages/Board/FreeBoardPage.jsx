import React, { useState } from "react";
import NavBar from "../../components/Main/NavBar";
import Banner1 from "../../components/Board/FreeBoardBanner";
import BoardSearchBox from "../../components/Board/BoardSearchBox";
import BoardList from "../../components/Board/FreeBoardList";
import MoveBoardRegisterButton from "../../components/Board/MoveBoardRegisterButton";
import "../../components/Board/css/FreeBoardBanner.css";

function FreeBoardPage() {
  const [searchResults, setSearchResults] = useState([]); // 검색 결과 상태

  return (
    <div className="container">
      <div className="box">
        <NavBar />
        <div>
          <Banner1 />
        </div>
        <BoardSearchBox setSearchResults={setSearchResults} />
        <div className="banner-spacing-top2">
          <BoardList boards={searchResults} />{" "}
          {/* 검색 결과를 BoardList로 전달 */}
        </div>
        <div className="MoveBoardRegisterButton">
          <MoveBoardRegisterButton />
        </div>
      </div>
    </div>
  );
}

export default FreeBoardPage;
