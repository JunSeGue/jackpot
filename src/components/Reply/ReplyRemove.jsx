import React from "react";
import Button from "@mui/material/Button";
import apiClient from "../../token/AxiosConfig";

const ReplyRemove = ({ replyId, onReplyDelete }) => {
  const handleDelete = async () => {
    if (window.confirm("정말로 이 댓글을 삭제하시겠습니까?")) {
      try {
        await apiClient.delete(`/reply/remove/${replyId}`);
        console.log("댓글 삭제 성공");

        // 댓글 삭제 후 갱신
        onReplyDelete();
      } catch (error) {
        console.error("댓글 삭제 실패:", error);
        alert("댓글 삭제에 실패했습니다.");
      }
    }
  };

  return (
    <Button variant="text" style={{ color: "red" }} onClick={handleDelete}>
      삭제하기
    </Button>
  );
};

export default ReplyRemove;
