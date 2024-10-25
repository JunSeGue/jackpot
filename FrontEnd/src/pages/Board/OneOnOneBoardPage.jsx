import React, { useState } from "react";
import NavBar from "../../components/Main/NavBar";
import Banner2 from "../../components/Board/OneOnOneBoardBanner";
import BoardSearchBox from "../../components/Board/BoardSearchBox";
import BoardList from "../../components/Board/OneOnOneBoardList";
import MoveBoardRegisterButton from "../../components/Board/MoveBoardRegisterButton";

import "../../components/Board/css/FreeBoardBanner.css";

function OneOnOneBoardPage() {
  const [searchResults, setSearchResults] = useState([]); // 검색 결과 상태

  return (
    <div className="container">
      <div className="box">
        <NavBar />
        <div>
          <Banner2 />
        </div>
        <BoardSearchBox setSearchResults={setSearchResults} />
        <div className="banner-spacing-top2">
          <BoardList boards={searchResults} />
        </div>
        <div className="MoveBoardRegisterButton">
          <MoveBoardRegisterButton />
        </div>
      </div>
    </div>
  );
}

export default OneOnOneBoardPage;
