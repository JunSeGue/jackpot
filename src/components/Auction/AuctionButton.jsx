import React from "react";
import styled from "styled-components";
import theme from "../../config/theme";
import {useNavigate} from "react-router-dom";

const AuctionButton = ({text, onClick = null}) => {
    const navigate = useNavigate();

    const buttonHref = () => {
        if (text === "뒤로가기") {
            window.history.back(); // history.back() 호출
        } else if (text === "입장하기") {
            navigate("/auction/bid"); // 원하는 경로로 이동
        } else if (text === "나가기") {
            navigate("/auction");
        } else if (text === "입찰하기"){
        }
    }

    return (
        <StyledWrapper>
            <button onClick={onClick || buttonHref}>{text}</button>
        </StyledWrapper>
    );
};

const StyledWrapper = styled.div`
  button {
    background-color: ${theme.colors.lightOrange};
    border: 1px solid rgb(209, 213, 219);
    border-radius: 0.5rem;
    color: #ffffff;
    font-size: 1.5rem;
    font-weight: 600;
    line-height: 1.25rem;
    padding: 0.75rem 1rem;
    text-align: center;
    -webkit-box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    cursor: pointer;
    -moz-user-select: none;
    -ms-user-select: none;
    user-select: none;
    -webkit-user-select: none;
    -ms-touch-action: manipulation;
    touch-action: manipulation;
    width: 300px;
  }

  button:hover {
    background-color: ${theme.colors.lightBeige};
    color: #000000;
  }

  button:focus {
    outline: 2px solid rgba(0, 0, 0, 0.1);
    outline-offset: 2px;
  }

  button:focus-visible {
    -webkit-box-shadow: none;
    box-shadow: none;
  }

`;

export default AuctionButton;
