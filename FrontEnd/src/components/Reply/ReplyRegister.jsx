import React, { useState } from "react";
import Button from "@mui/material/Button";
import apiClient from "../../token/AxiosConfig";
import { useNavigate } from "react-router-dom";
import "./css/ReplyRegister.css"

const ReplyForm = ({ boardId, onReplySubmit }) => {
  const [replyContent, setReplyContent] = useState("");
  const navigate = useNavigate();

  const handleSubmit = async () => {
    try {
      const response = await apiClient.post("/reply/register", {
        boardId: boardId,
        content: replyContent,
      });
      console.log("댓글 등록 성공:", response.data);

      alert("댓글이 등록되었습니다.");

      // 댓글 작성 완료 후 콜백 호출
      onReplySubmit();

      // 현재 페이지로 다시 이동 (리디렉션)
      navigate(0); // 이 코드는 현재 페이지를 리로드합니다.
    } catch (error) {
      console.error("댓글 등록 실패:", error);
    }
  };

  return (
    <div className="w-full flex align-center justify-center">
    <textarea
      className="reply-textarea h-full"
      value={replyContent}
      onChange={(e) => setReplyContent(e.target.value)}
      placeholder="댓글을 입력하세요."
    />
    <Button 
      variant="text" 
      className="reply-button flex align-center justify-center" 
      onClick={handleSubmit}
    >
      댓글 등록
    </Button>
  </div>
  );
};

export default ReplyForm;

