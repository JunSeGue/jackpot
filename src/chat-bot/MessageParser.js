import { apiNoToken } from "../token/AxiosConfig";

class MessageParser {
  constructor(actionProvider, state) {
    this.actionProvider = actionProvider;
    this.state = state;
  }

  parse(message) {
  
    // 백엔드로 메시지 전송
    apiNoToken.post("/api/chatbot/send", 
      {
        message:message,
      },
      {
      headers: {
        "Content-Type": "application/json",
      }
    }
  )
      .then((response) => {
        
        // data.message가 실제로 존재하는지 확인하고 처리
        if (response.data && response.data.message) {
          this.actionProvider.handleBotResponse(response.data.message);
        } else {
          console.error("Invalid response format:", response.data);
        }
      })
      .catch((error) => {
        console.error("Error:", error);
      });
  }
}  

export default MessageParser;
