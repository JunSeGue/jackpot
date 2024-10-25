import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import apiClient from "../../token/AxiosConfig.js";
import "./css/BoardList.css";

const FreeBoardList = ({ boards }) => {
  // props로 boards를 받음
  const [type1Boards, setType1Boards] = useState([]); // 공지글 목록 상태
  const [type2Boards, setType2Boards] = useState([]); // 자유글 목록 상태
  const [loading, setLoading] = useState(true); // 로딩 상태
  const [page, setPage] = useState(1); // 현재 페이지 번호
  const [totalPages, setTotalPages] = useState(1); // 전체 페이지 수

  useEffect(() => {
    // 검색 결과가 없을 경우에만 기본 게시물 목록을 가져옴
    if (boards.length === 0) {
      const fetchBoards = async () => {
        try {
          const response = await apiClient.get("board/findAll", {
            params: { page, size: 10 }, // 페이지와 페이지 사이즈 요청
          });
          const allBoards = response.data.dtoList || [];
          // console.log(allBoards);

          // 공지글과 자유글 분리
          const filteredType1 = allBoards.filter(
            (boardDTO) => boardDTO.type === 1
          );
          const filteredType2 = allBoards.filter(
            (boardDTO) => boardDTO.type === 2
          );
          // console.log(filteredType1);
          // console.log(filteredType2);

          setType1Boards(filteredType1); // 공지글 설정
          setType2Boards(filteredType2); // 자유글 설정

          setTotalPages(response.data.total); // 전체 페이지 수 설정
          setLoading(false);
        } catch (error) {
          console.error("데이터 가져오기 실패:", error);
          setLoading(false);
        }
      };

      fetchBoards();
    } else {
      setLoading(false); // 검색 결과가 있으면 로딩 상태 해제
    }
  }, [page, boards]); // boards가 바뀔 때마다 재렌더링

  if (loading) {
    return <div>로딩 중...</div>;
  }

  const displayedBoards =
    boards.length > 0 ? boards : [...type1Boards, ...type2Boards]; // 검색 결과가 있을 때는 boards 사용

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setPage(newPage);
    }
  };

  return (
    <div className="board-list">
      <table className="board-table">
        <thead>
          <tr>
            <th>글유형</th>
            <th>글번호</th>
            <th>제목</th>
            <th>작성자</th>
            <th>작성일</th>
          </tr>
        </thead>
        <tbody>
          {displayedBoards.length > 0 ? (
            displayedBoards.map((boardDTO) => (
              <tr key={boardDTO.boardId}>
                <td>{boardDTO.type === 1 ? "공지" : "자유"}</td>
                <td>{boardDTO.boardId}</td>
                <td>
                  <Link
                    to={`/board/${boardDTO.boardId}`}
                    style={{ textDecoration: "none", color: "black" }}
                  >
                    {boardDTO.title}
                  </Link>
                </td>
                <td>
                  {boardDTO.memberId ? boardDTO.memberId : "작성자 정보 없음"}
                </td>
                <td>{boardDTO.regDate}</td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="5">게시글이 없습니다.</td>
            </tr>
          )}
        </tbody>
      </table>

      {/* 페이지네이션 버튼 */}
      {boards.length === 0 && ( // 검색 결과가 없을 때만 페이지네이션 버튼 표시
        <div className="pagination">
          <button
            onClick={() => handlePageChange(page - 1)}
            disabled={page === 1}
          >
            이전
          </button>
          <span>
            {page} / {totalPages}
          </span>
          <button
            onClick={() => handlePageChange(page + 1)}
            disabled={page === totalPages}
          >
            다음
          </button>
        </div>
      )}
    </div>
  );
};

export default FreeBoardList;
