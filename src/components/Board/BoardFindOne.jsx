import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import apiClient from "../../token/AxiosConfig";
import ReplyForm from "../Reply/ReplyRegister";
import ReplyList from "../Reply/ReplyFindAll";
import { useNavigate } from "react-router-dom";
import "./css/BoardFindOne.css";

const BoardFindOne = () => {
  const { boardId } = useParams();
  const [board, setBoard] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchBoard = async () => {
      try {
        const response = await apiClient.get("board/findOne", {
          params: { boardId: boardId },
        });
        console.log("Board Data:", response);

        setBoard(response.data);
        setLoading(false);
      } catch (error) {
        console.error("게시글 불러오기 실패:", error);
        setLoading(false);
      }
    };

    fetchBoard();
  }, [boardId]);

  const handleReplySubmit = async () => {
    try {
      const response = await apiClient.get("board/findOne", {
        params: { boardId: boardId },
      });
      setBoard(response.data);
    } catch (error) {
      console.error("게시글 갱신 실패:", error);
    }
  };

  console.log("BoardFindOne boardId:", boardId);

  if (loading) {
    return <div>로딩 중...</div>;
  }

  if (!board) {
    return (
      <div style={{ marginTop: "140px", marginBottom: "140px" }}>
        게시글을 불러오는데 실패했습니다.
        <br />
        <br /> 혹은 로그인이 필요합니다.
      </div>
    );
  }

  return (
    <div className="board-read-container flex flex-column justify-center w-half">
      <table className="board-read-table w-full">
        <thead>
          <tr>
            <td>
              <b>{board.boardId}번 글</b> <h1>{board.title}</h1>
              {board.memberId} | {board.regDate} 작성
            </td>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td className="board-content">{board.content}</td>
          </tr>
          <tr>
            <td>
              <ReplyForm boardId={boardId} onReplySubmit={handleReplySubmit} />
            </td>
          </tr>
        </tbody>
        <tfoot>
          <ReplyList boardId={boardId} />
        </tfoot>
      </table>
      <div className="button-container flex justify-end w-full">
        <Link
          to={`/board/edit/${board.boardId}`}
          className="link-button edit-button"
        >
          수정하기
        </Link>
        <Link
          to={`/board/remove/${board.boardId}`}
          className="link-button remove-button"
        >
          삭제하기
        </Link>
      </div>
    </div>
  );
};

export default BoardFindOne;
