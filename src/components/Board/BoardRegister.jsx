import React, { useState, useEffect } from "react";
import apiClient from "../../token/AxiosConfig";
import { useNavigate } from "react-router-dom";
import Button from "@mui/material/Button"; // Material-UI의 Button 컴포넌트
import "./css/BoardRegister.css";

const BoardRegister = () => {
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [type, setType] = useState("2");
  const [currentDateTime, setCurrentDateTime] = useState("");
  const navigate = useNavigate();

  // useEffect(() => {
  //   const now = new Date();
  //   const formattedDateTime = now.toISOString();
  //   setCurrentDateTime(formattedDateTime);
  // }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();

    // console.log(currentDateTime);

    const formData = new FormData();
    formData.append("title", title);
    formData.append("content", content);
    formData.append("regDate", currentDateTime);
    formData.append("type", type);

    // try {
    //   const response = await apiClient.post("board/register", {
    //     title: title,
    //     content: content,
    //     type: type,
    //     regDate: currentDateTime,
    //   });

    try {
      const response = await apiClient.post("board/register", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      console.log("게시글 작성 성공:", response.data);
      alert("게시글이 저장되었습니다.");
      if (response.data.status === 200 || response.status === 200) {
        navigate("/freeBoard");
      }
    } catch (error) {
      console.error(error.response ? error.response.data : error.message);
    }
  };

  return (
    <div className="flex flex-column align-center">
      <form onSubmit={handleSubmit}>
        <div className="flex justify-between items-center w-half p-2">
          <h2 className="align-left p-2">게시글 작성하기</h2>
        </div>

        <div className="m-auto">
          <table className="board-table-reg w-full">
            <thead>
              <tr>
                <td>
                  <input
                    className="w-full p-2"
                    type="text"
                    placeholder="제목"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </td>
                <td
                  className="w-thirty"
                  style={{ padding: "10px", borderTopRightRadius: "8px" }}
                >
                  <select
                    value={type}
                    onChange={(e) => setType(e.target.value)}
                    required
                    style={{ width: "90%", height: "40px" }}
                  >
                    <option value="2">자유게시판</option>
                    <option value="3">문의게시판</option>
                  </select>
                </td>
              </tr>
            </thead>

            <tbody>
              <tr>
                <td colSpan={2} className="">
                  <h4 className="text-left" style={{ marginLeft: "10px" }}>
                    아래에 본문 작성
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
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    required
                    placeholder="내용"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div style={{ marginTop: "16px", textAlign: "right" }}>
          <Button type="submit" variant="contained" className="save-button">
            저장하기
          </Button>
        </div>
      </form>
    </div>
  );
};

export default BoardRegister;
