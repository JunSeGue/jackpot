import React, { useState, useEffect } from "react";
import { useParams, useLocation } from "react-router-dom";
import Info from "../../detailComponent/Info";
import YouTubeContainer from "../../detailComponent/YoutubeContainer";
import DogHistory from "../../detailComponent/DogHistory";
import FundStory from "../../detailComponent/FundStory";
import styled from "styled-components";
import apiClient from "../../token/AxiosConfig";

const DogDetail = () => {
  const { dogId } = useParams();
  const [dogData, setDogData] = useState({});
  const location = useLocation();

  useEffect(() => {
    // 성공 메시지 확인 및 기본 alert 창 표시
    if (location.state?.successMessage) {
      alert(location.state.successMessage); 
    }
    apiDogDetail();
  }, [dogId, location.state]);

  const apiDogDetail = async () => {
    try {
      const response = await apiClient.get("dog/findOne", {
        params: { dogId: dogId },
      });
      const transformedData = {
        ...response.data,
        gender: response.data.gender === 1 ? "여성" : "남성",
        age: `${response.data.age}세`,
      };

      setDogData(transformedData);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <>
      {dogData?.dogId && (
        <StyledContainer>
          <div className="section-dogDetail">
            <Info dogData={dogData} />

            <div className="flex flex-column align-center justify-center w-full">
              {dogData.videoUrl && (
                <YouTubeContainer youtubeLink={dogData.videoUrl} />
              )}
              <FundStory />
            </div>
            <DogHistory dogData={dogData} />
          </div>
        </StyledContainer>
      )}
    </>
  );
};
export default DogDetail;

const StyledContainer = styled.div`
  width: 100%;
  margin-left: auto;
  margin-right: auto;
  box-sizing: border-box;
  padding-left: 16px;
  padding-right: 16px;
  margin-top: 100px;
  min-height: 100vh;
  @media (min-width: 600px) {
    padding-left: 24px;
    padding-right: 24px;
  }
  @media (min-width: 1200px) {
    max-width: 1200px;
  }

  .detail-wrapper {
    box-shadow: 5px 5px 10px 2px #3333;
    border-radius: 8px;
    padding: 20px;
  }
`;
