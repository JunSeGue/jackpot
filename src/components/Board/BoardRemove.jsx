import React, { useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom"; // URL 파라미터와 페이지 이동을 위한 임포트
import apiClient from "../../token/AxiosConfig.js"; // Axios 인스턴스 임포트

const BoardRemove = () => {
  const { boardId } = useParams(); // URL에서 boardId 가져오기
  const navigate = useNavigate(); // 페이지 이동을 위한 navigate

  useEffect(() => {
    // 사용자에게 삭제 확인 팝업을 띄움
    const confirmDelete = window.confirm("게시글을 삭제하겠습니까?");
    if (!confirmDelete) {
      navigate("/freeBoard"); // 사용자가 취소하면 목록 페이지로 이동
      return; // 삭제를 취소함
    }

    const fetchBoard = async () => {
      try {
        const response = await apiClient.delete(`board/remove/${boardId}`);

        console.log(response);

        // 삭제 성공 후 원하는 동작: 게시판 목록으로 이동
        if (response.status === 200) {
          navigate("/freeBoard"); // 게시글 삭제 후 게시판 목록 페이지로 이동
        }
      } catch (error) {
        console.error("게시글 삭제 실패:", error);
      }
    };

    fetchBoard();
  }, [boardId, navigate]); // boardId와 navigate가 변경될 때마다 실행

  return <div></div>;
};

export default BoardRemove;
