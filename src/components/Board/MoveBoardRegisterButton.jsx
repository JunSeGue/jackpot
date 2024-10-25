import React from "react";
import BoardRegisterPen from "../../static/BoardRegisterPen.png";
import { useNavigate } from "react-router-dom";
import "./css/MoveBoardRegisterButton.css";

const MoveBoardRegisterButton = () => {
  const navigate = useNavigate();

  return (
    <div className="register-button-container">
      <button
        type="submit"
        className="register-button"
        onClick={() => navigate("/board/register")}
      >
        글 작성
        <img
          src={BoardRegisterPen}
          alt="글 작성"
          className="register-button-icon"
        />
      </button>
    </div>
  );
};

export default MoveBoardRegisterButton;
