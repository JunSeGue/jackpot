import React from "react";
import Banner1 from "../../components/Board/FreeBoardBanner";
import BoardRemove from "../../components/Board/BoardRemove";
// import "../components/Board/css/BoardEdit.css";
import "../../components/Board/css/FreeBoardBanner.css";
import Button from "@mui/material/Button";
import { useNavigate } from "react-router-dom";

const BoardEditting = () => {
  const navigate = useNavigate();

  return (
    <>
      <div className="banner-spacing-top">
        <Banner1 />
      </div>
      <div className="register-spacing-top">
        <BoardRemove />
        <h2>게시글이 삭제되었습니다.</h2>
        <Button
          variant="contained"
          style={{
            fontWeight: "bold",
            backgroundColor: "skyblue",
          }}
          onClick={() => {
            navigate("/freeBoard");
          }}
        >
          목차로 돌아가기
        </Button>
      </div>
    </>
  );
};

export default BoardEditting;
