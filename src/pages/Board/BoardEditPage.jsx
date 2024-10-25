import React from "react";
import Banner5 from "../../static/Banner5mod.png";
import BoardEdit from "../../components/Board/BoardEdit";
import "../../components/Board/css/FreeBoardBanner.css";

const BoardEditting = () => {
  return (
    <div className="container">
      <div>
        <img
          src={Banner5}
          alt="글 조회하기 배너"
          style={{ width: "50%", margin: "0 auto", position: "relative" }}
        />
      </div>
      <div>
        <BoardEdit />
      </div>
    </div>
  );
};

export default BoardEditting;
