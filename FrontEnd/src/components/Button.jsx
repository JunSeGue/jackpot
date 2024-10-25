import React, { useState } from "react";
import styled from "styled-components";
import HeadsetMicIcon from "@mui/icons-material/HeadsetMic";
import Chatbot from "react-chatbot-kit";
import config from "../chat-bot/config.js";
import MessageParser from "../chat-bot/MessageParser.js";
import ActionProvider from "../chat-bot/ActionProvider.js";
import "../chat-bot/style.css";
import "remixicon/fonts/remixicon.css";
import theme from "../config/theme.js";

const Button = () => {
  const [isChatbotOpen, setChatbotOpen] = useState(false);

  const chatOpen = () => {
    setChatbotOpen(true); // 챗봇 토글
  };

  const chatClose = () => {
    setChatbotOpen(false); // 챗봇 닫기
  };

  return (
    <>
      <StyledWrapper>
        <button onClick={chatOpen}>
          <HeadsetMicIcon
            style={{ color: "white", width: "30", height: "30" }}
          />
        </button>
        {isChatbotOpen && (
          <>
            <Chatbot
              config={config(chatClose)}
              messageParser={MessageParser}
              actionProvider={ActionProvider}
            />
          </>
        )}
      </StyledWrapper>
    </>
  );
};

const StyledWrapper = styled.div`
  button {
    width: 70px;
    height: 70px;
    bottom: 40px;
    right: 40px;
    background-color: ${theme.colors.lightOrange};
    color: #fff;
    border-radius: 50px;
    text-align: center;
    font-size: 30px;
    box-shadow: 2px 2px 3px #999;
    z-index: 1000;
    border: #004dff;
    transition: 0.5s;
    position: fixed;
  }

  button:hover {
    transform: scale(1.1);
  }

  button:active {
    background-color: #020cd1;
  }

  .arrow-up {
    width: 0;
    height: 0;
    border-left: 10px solid transparent;
    border-right: 10px solid transparent;
    margin: 35% auto 60%;
    border-bottom: 15px solid white;
  }

  .chat-bot {
    width: 0;
    height: 0;
    border-left: 10px solid transparent;
    border-right: 10px solid transparent;
    margin: 35% auto 60%;
    border-bottom: 15px solid white;
  }
`;

export default Button;
