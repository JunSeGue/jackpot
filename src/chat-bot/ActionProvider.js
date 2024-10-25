class ActionProvider {
  constructor(createChatbotMessage, setStateFunc, createClientMessage) {
    this.createChatbotMessage = createChatbotMessage;
    this.setState = setStateFunc;
    this.createClientMessage = createClientMessage;
  }
  handleBotResponse = (message) => {
    // console.log("Bot response received:", message);
    const botMessage = this.createChatbotMessage(message);
    // console.log("Bot message created:", botMessage);
    this.setState((prevState) => ({
      ...prevState,
      messages: [...prevState.messages, botMessage],
    }));
  };
  
}

export default ActionProvider;
