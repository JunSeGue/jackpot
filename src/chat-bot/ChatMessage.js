import styled from "styled-components";
import React from "react";
import themes from "../config/theme";

const ChatMessageContainer = styled.div`
 max-width: 85%;
  width: fit-content;
  display: flex;
  justify-content: ${(props) => (props.$isbot === "true" ? "flex-start" : "flex-end")};
  background-color: ${(props) => (props.$isbot === "true" ? "#f2f2f2" : themes.colors.lightOrange)};
  border-radius: ${(props) => (props.$isbot === "true" ? "20px 20px 20px 5px" : "20px 20px 5px 20px")};
  margin-left: ${(props) => (props.$isbot === "true" ? "0.4rem" : "auto")};
  margin-right: ${(props) => (props.$isbot === "true" ? "auto" : "0.4rem")};
  color: ${(props) => (props.$isbot === "true" ? "#3d4f6e" : "#ffffff")};
  padding: ${(props) => (props.$isbot === "true" ? "0.8rem 1.2rem" : "0.7rem 1.1rem")};
  font-weight: ${(props) => (props.$isbot === "true" ? "500" : "400")};
  font-size: 0.97rem;
  line-height: 1.3rem;
  word-break: keep-all;
`;

function ChatMessage({ message, isbot }) {
  return <ChatMessageContainer $isbot={isbot}>{message}</ChatMessageContainer>;
}

export default ChatMessage;
