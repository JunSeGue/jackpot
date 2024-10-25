import React, { useState, useEffect } from "react";
import apiClient from "../../token/AxiosConfig"; // apiClient 임포트
import { useNavigate, useParams } from "react-router-dom";
import Button from "@mui/material/Button";
import "./css/BoardRegister.css";

const BoardEdit = () => {
  const { boardId } = useParams(); // URL에서 게시글 ID를 받아옴
  const [title, setTitle] = useState(""); // 게시글 제목 상태
  const [content, setContent] = useState(""); // 게시글 내용 상태
  const navigate = useNavigate(); // 페이지 이동을 위한 navigate
  const [currentDateTime, setCurrentDateTime] = useState(""); // 현재 시간 상태

  // // 현재 시간과 날짜를 가져오는 함수
  // useEffect(() => {
  //   const now = new Date();
  //   const formattedDateTime = now.toISOString(); // 현재 시간을 ISO 형식으로 변환
  //   setCurrentDateTime(formattedDateTime); // 상태 업데이트
  // }, []);

  // 기존 게시글 데이터를 가져오는 함수
  useEffect(() => {
    const fetchBoardData = async () => {
      try {
        const response = await apiClient.get("board/findOne", {
          params: { boardId: boardId },
        });
        const board = response.data;
        setTitle(board.title); // title 값을 설정
        setContent(board.content); // content 값을 설정
      } catch (error) {
        console.error("게시글 데이터를 가져오는 중 에러:", error);
      }
    };

    fetchBoardData();
  }, [boardId]);

  const handleSubmit = async (e) => {
    e.preventDefault(); // 기본 폼 제출 방지

    // console.log(currentDateTime);

    const formData = new FormData();
    formData.append("title", title);
    formData.append("content", content);
    formData.append("regDate", currentDateTime);
    // formData.append("type", type);

    // try {
    //   const response = await apiClient.post(`/board/edit/${boardId}`, {
    //     title: title,
    //     content: content,
    //     regDate: currentDateTime, // 현재 시간
    //   });
    try {
      const response = await apiClient.post(`board/edit/${boardId}`, formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      console.log("게시글 수정 성공:", response.data);
      if (response.data.status === 200 || response.status === 200) {
        navigate("/freeBoard");
      }
    } catch (error) {
      console.error(error.response ? error.response.data : error.message);
    }
  };

  return (
    <>
      <div className="flex flex-column align-center">
        <form onSubmit={handleSubmit}>
          <div className="flex justify-between items-center w-half p-2">
            <h2 className="align-left p-2">게시글 수정하기</h2>
          </div>
          <div className="m-auto">
            <table className="board-table-reg w-full">
              <thead>
                <tr>
                  <td>
                    <input
                      className="w-full p-2"
                      type="text"
                      placeholder="수정할 제목"
                      value={title}
                      onChange={(e) => setTitle(e.target.value)}
                      required
                    />
                  </td>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td colSpan={2} className="">
                    <h4 className="text-left" style={{ marginLeft: "10px" }}>
                      아래에 수정내용 작성
                    </h4>
                  </td>
                </tr>
                <tr>
                  <td
                    colSpan={2}
                    style={{ padding: "8px", borderBottom: "1px solid #ccc" }}
                  >
                    <textarea
                      className="contentArea"
                      value={content} // 기존 내용을 표시
                      onChange={(e) => setContent(e.target.value)} // 새로운 내용 입력 시 상태 업데이트
                      required
                      placeholder="수정할 내용"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: "16px", textAlign: "right" }}>
            <Button type="submit" variant="contained" className="save-button">
              수정하기
            </Button>
          </div>
        </form>
      </div>
    </>
  );
};

export default BoardEdit;
