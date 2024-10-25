import { useEffect, useState } from "react";
import styled from "styled-components";
import apiClient from "../token/AxiosConfig";
import { NoneContent } from "../pages/Memeber/Mypage";

import { ProgressBar } from "./ProgressBar";
import { Avatar } from "@mui/material";
import getTimeAgo from "../detailComponent/GetTImeAgo";
import AnimatedNumber from "./AnimatedNumber";

export const FundHistorySection = ({ showAll }) => {
  const [fundDTO, setFundDTO] = useState([]);

  useEffect(() => {
    const apiFunding = async () => {
      try {
        const response = await apiClient.get("dog/fundListMyPage");
        const { fundList, dogResponseList } = response.data;
        console.log(response, "1111111111111111111111111111");
        // fundList에 있는 정보만을 우선적으로 사용
        const extractedData = fundList?.map((fund) => {
          const dog = dogResponseList?.find((dog) => dog.dogId === fund.dogId); // dogResponseList가 있을 때만 찾음
          return {
            regDate: fund.regDate,
            name: dog.name,
            fundCollection: dog.fundCollection,
            collection: fund.collection,
            title: dog.title,
            species: dog.species,
            age: dog.age,
            fundMemberNum: dog.fundMemberNum,
            gender: dog.gender === 1 ? "남성" : "여성",
            heart: dog.heart,
            mainImage: dog.mainImage,
          };
        });
        setFundDTO(extractedData);
      } catch (error) {
        console.log(error);
      }
    };
    apiFunding();
  }, []);
  console.log(fundDTO);

  const displayedData = showAll ? fundDTO : fundDTO.slice(0, 3);

  const FundItem = ({ fund }) => {
    console.log(fund);
    return (
      <StyledFundingSection className="flex flex-row">
        <h5 className="funding-title">{fund.title}</h5>
        {/* 왼쪽: 이미지와 이름 */}
        <div className="flex flex-column align-center">
          <Avatar
            alt={fund.name}
            src={fund.mainImage}
            sx={{ width: 150, height: 150, marginBottom: 2, boxShadow: 3 }}
          />
          <p style={{ fontSize: "1.5rem", fontWeight: "bold", margin: 0 }}>
            {fund.name}
          </p>
        </div>

        {/* 오른쪽: 개 정보 (두 개의 열로 구성) */}

        <StyledFundDetailSection>
          <div className="section-dogInfo w-full">
            <div className="dogInfo-grid">
              <div className="grid-item">
                <p style={{ fontWeight: "bold" }}>나이</p>
                <p>{fund.age}살</p>
              </div>
              <div className="grid-item">
                <p style={{ fontWeight: "bold" }}>성별</p>
                <p>{fund.gender}</p>
              </div>
              <div className="grid-item">
                <p style={{ fontWeight: "bold" }}>좋아요 수</p>
                <p>{fund.heart}</p>
              </div>
              <div className="grid-item">
                <p style={{ fontWeight: "bold" }}>품종</p>
                <p>{fund.species}</p>
              </div>
            </div>
            <div className="regDate-section flex justify-end">
              <span className="regDate">{fund.regDate.slice(0, 10)}</span>
              <span className="regDateAgo">{getTimeAgo(fund.regDate)}</span>
            </div>
          </div>
          <div className="section-progressBar p-0 w-full">
            <span style={{ fontWeight: "bold", marginRight: "20px" }}>
              후원금액
            </span>
            <span>
              <AnimatedNumber value={fund.collection} />
            </span>
            <ProgressBar
              value={fund.collection}
              fundCollection={fund.fundCollection}
            />
          </div>
        </StyledFundDetailSection>
      </StyledFundingSection>
    );
  };

  return (
    <StyledFundHistory>
      <h4 className="text-left p-0 m-0">펀딩 내역</h4>
      {fundDTO?.length ? (
        displayedData.map((fund, index) => <FundItem key={index} fund={fund} />)
      ) : (
        <NoneContent />
      )}
    </StyledFundHistory>
  );
};

const StyledFundHistory = styled.div`
  width: 100%;
  .section-fundingHistory {
    display: flex;
    align-items: center;
    padding: 20px;
    border-bottom: 1px solid #ddd;
    margin-bottom: 20px;
    flex-wrap: wrap;
    justify-content: flex-start;
  }

  h5 {
    font-size: 1.3rem;
    text-align: center;
    width: 100%;
  }
`;
// --------------------------------------------------
const StyledFundingSection = styled.div`
  border-radius: 8px;
  width: 100%;
  background-color: white;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  padding: 30px 0;
  align-items: center;
  justify-content: space-around;
  flex-wrap: wrap;
  align-items: center;

  h5 {
    font-size: 1.5rem;
    font-weight: bold;
    text-align: left;
    padding-left: 20px;
  }
`;
const StyledFundDetailSection = styled.div`
  display: flex;
  flex-direction: column;

  p {
    margin: 0;

    strong {
      font-weight: bold;
    }
  }
  .dogInfo-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr); /* 2열로 나누기 */
    gap: 10px;
    border: 1px solid #3333;
    box-shadow: 10px -20px 15px rgba(255, 161, 80, 0.8);
  }
  .grid-item {
    display: flex;
    flex-direction: column;
  }
  .regDate-section {
    font-size: 0.7rem;
    gap: 20px;
    margin-top: 20px;
  }
`;
