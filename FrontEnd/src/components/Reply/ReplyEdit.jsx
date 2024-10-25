import React, { useState } from "react";
import apiClient from "../../token/AxiosConfig";

const ReplyEdit = ({ reply, boardId, onReplyUpdate, setEditingReplyId }) => {
  const [newContent, setNewContent] = useState(reply.content);

  const handleUpdate = async () => {
    try {
      await apiClient.put(`/reply/edit/${reply.replyId}`, {
        boardId: boardId,
        content: newContent,
      });

      console.log("댓글 수정 성공");

      // 댓글 수정 후 목록 갱신
      onReplyUpdate(); // 여기서 함수가 호출됨

      // 수정 완료 후 편집 모드 해제
      setEditingReplyId(null);
    } catch (error) {
      console.error("댓글 수정 실패:", error);
    }
  };

  return (
    <div>
      <textarea
        value={newContent}
        onChange={(e) => setNewContent(e.target.value)}
      />
      <button onClick={handleUpdate}>수정 완료</button>
    </div>
  );
};

export default ReplyEdit;
