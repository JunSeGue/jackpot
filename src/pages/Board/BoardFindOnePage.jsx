import React from "react";
import BoardFindOne from "../../components/Board/BoardFindOne";
import Banner3 from "../../static/Banner3mod.png";

const BoardFindOnePage = () => {
  return (
    <div className="container flex flex-column align-center">
      <img
        src={Banner3}
        alt="글 조회하기 배너"
        style={{ width: "50%", margin: "0 auto", position: "relative" }}
      />
      <BoardFindOne className="flex flex-column align-start" />
    </div>
  );
};

export default BoardFindOnePage;
