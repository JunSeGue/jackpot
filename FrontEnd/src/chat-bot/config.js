
import { createChatBotMessage } from "react-chatbot-kit";
import Header from "./Header";
import ChatMessage from "./ChatMessage";
import ActionProvider from "./ActionProvider"; // 추가
import MessageParser from "./MessageParser"; // 추가

const config = (onCloseChatbot) => ({
  initialMessages: [
    createChatBotMessage(
      "안녕하세요! 궁금한 내용을 입력해주세요."
    ),
  ],
  customComponents: {
    // Replaces the default header
    header: () => <Header onCloseChatbot={onCloseChatbot} />,
    // Replaces the default bot avatar
    botAvatar: (props) => <div {...props} />,
    // Replaces the default bot chat message container
    botChatMessage: (props) => <ChatMessage {...props} isbot="true" />,
    // Replaces the default user icon
    userAvatar: (props) => <div {...props} />,
    // Replaces the default user chat message
    userChatMessage: (props) => <ChatMessage {...props} isbot="false"/>,
  },
  // 추가: ActionProvider와 MessageParser를 설정
  actionProvider: ActionProvider,
  messageParser: MessageParser,
});

export default config;
