import React from "react";
import Banner2 from "../../static/Banner2mod.png";
import "./css/FreeBoardBanner.css";
import Button from "@mui/material/Button";
import { useNavigate } from "react-router-dom";

const OneOnOneBoardBanner = () => {
  const navigate = useNavigate();
  return (
    <div className="flex flex-column">
      <Button
        className="oneOnOneButton fixed"
        variant="text"
        style={{ color: "#ff7600" }}
        onClick={() => {
          navigate("/freeBoard");
        }}
      >
        자유게시판으로 가기 →
      </Button>
      <div className="banner-container relative banner-margin-0">
        <img
          src={Banner2}
          alt="1:1 문의 게시판 배너 이미지"
          className="banner-img"
        />
      </div>
    </div>
  );
};

export default OneOnOneBoardBanner;
