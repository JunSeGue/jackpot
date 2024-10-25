import React, { useEffect, useState } from "react";
import apiClient from "../../token/AxiosConfig";
import ReplyEditForm from "./ReplyEdit";
import ReplyDeleteButton from "./ReplyRemove"; // 삭제 버튼 컴포넌트 추가
import "./css/ReplyFindAll.css";

const ReplyList = ({ boardId }) => {
  const [replies, setReplies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingReplyId, setEditingReplyId] = useState(null); // 수정할 댓글 ID 상태

  // 댓글 목록을 갱신하는 함수
  const fetchReplies = async () => {
    try {
      const response = await apiClient.get("/reply/findAll", {
        params: { boardId: boardId },
      });
      setReplies(response.data);
      setLoading(false);
    } catch (error) {
      console.error("댓글 불러오기 실패:", error);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReplies();
  }, [boardId]);

  const handleReplyUpdate = () => {
    fetchReplies(); // 댓글이 수정되거나 삭제되면 목록을 다시 불러옵니다.
  };

  if (loading) {
    return (
      <tr>
        <td>댓글을 불러오는 중...</td>
      </tr>
    );
  }

  if (replies.length === 0) {
    return (
      <tr>
        <td>댓글이 없습니다.</td>
      </tr>
    );
  }

  return (
    <>
      {replies.map((reply) => (
        <tr key={reply.replyId}>
          <td>
            {editingReplyId === reply.replyId ? (
              <ReplyEditForm
                reply={reply}
                boardId={boardId}
                onReplyUpdate={handleReplyUpdate} // 수정 후 목록 갱신 함수 전달
                setEditingReplyId={setEditingReplyId}
              />
            ) : (
              <>
                <b>{reply.memberId}번 회원</b>: {reply.content} || (
                {reply.regDate})
                <button onClick={() => setEditingReplyId(reply.replyId)}>
                  수정하기
                </button>
                <ReplyDeleteButton
                  replyId={reply.replyId}
                  onReplyDelete={handleReplyUpdate} // 삭제 후 목록 갱신 함수 전달
                />
              </>
            )}
          </td>
        </tr>
      ))}
    </>
  );
};

export default ReplyList;
