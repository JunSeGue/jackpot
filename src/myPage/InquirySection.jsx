import { useEffect, useState } from "react";
import getTimeAgo from "../detailComponent/GetTImeAgo";
import { NoneContent } from "../pages/Memeber/Mypage";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import apiClient from "../token/AxiosConfig";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";

const InquirySection = ({ showAll }) => {
  const [inquiry, setInquiry] = useState([]) || {};
  const navigate = useNavigate();

  useEffect(() => {
    const apiOninquiry = async () => {
      try {
        const pageSize = showAll ? 10 : 3; // 최대 10개의 데이터를 가져옵니다.
        const response = await apiClient.get("board/findAllAskMyPage", {
          params: { page: 1, size: pageSize },
        });

        setInquiry(response.data);
      } catch (error) {
        console.error(error);
      }
    };
    apiOninquiry();
  }, [showAll]);

  return (
    <StyledOneBoard>
      <h4 className="text-left p-0 m-0">나의 문의내역</h4>
      {inquiry?.length ? (
        inquiry.map((board) => (
          <div
            key={board.boardId}
            className="section-oneBoard flex flex-row justify-between align-center"
          >
            <span className="left-oneBoard flex flex-row w-half ">
              <LockOutlinedIcon />
              1대1문의 내역입니다.
            </span>

            <span>{board.regDate.slice(0, 10)}</span>
            <span>{getTimeAgo(board.regDate)} </span>
            <button
              className="btn_show"
              onClick={() => {
                navigate(`/board/${board.boardId}`);
              }}
            >
              보러가기
            </button>
          </div>
        ))
      ) : (
        <NoneContent />
      )}
    </StyledOneBoard>
  );
};

export default InquirySection;

const StyledOneBoard = styled.div`
  .section-oneBoard {
    padding: 30px;
  }
  .left-oneBoard {
    align-self: center;
  }
`;