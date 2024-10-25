import React from "react";
import styled from "styled-components";

// 전체 스타일을 하나의 컨테이너 컴포넌트로 관리
const StyledContainer = styled.div`
  margin-top: 20px;
  padding: 10px;
  .box-wrapper {
    border-top: 1px solid black;
    border-bottom: 1px solid black;
    padding: 10px 0;
  }

  .title {
    text-align: left;
    margin: 0;
    padding: 0;
  }

  .history-section {
    margin: 20px 0;
    width: 100%;
    min-height: 400px;

    gap: 5%;
  }

  .pictures-section {
    flex: 1;
    display: grid;
    grid-template-columns: 1fr 1fr;
    column-gap: 30px;
    padding: 20px;
  }

  .pictures-section img {
    width: 100%;
    height: 150px;
    object-fit: cover;
    box-shadow: 0 0 10px 5px #666;
  }

  .pictures-section img:nth-child(even) {
    transform: translateY(70px); /* 짝수 번째 이미지 아래로 이동 */
  }

  .dog-info-section {
    flex: 1;
    padding: 0 20px;
    text-align: left;

    flex-direction: column;
    justify-content: center;
  }
`;

// 컴포넌트 렌더링
const History = ({ dogData }) => {
  const images = [
    dogData.detailImage1,
    dogData.detailImage2,
    dogData.detailImage3,
    dogData.detailImage4,
  ];
  console.log(dogData.name);
  return (
    <StyledContainer>
      <div className="box-wrapper">
        <h2 className="title">{dogData.name}의 History</h2>
      </div>
      <div className="history-section flex flex-row">
        <div className="pictures-section">
          {images.map((src, index) => (
            <img key={index} src={src} alt={`image-${index}`} />
          ))}
        </div>

        <div className="dog-info-section flex">
          <h3>{dogData.name}</h3>
          <p>나이: {dogData.age}</p>
          <p> {dogData.species}</p>
          <p>성별: {dogData.gender}</p>
          <p dangerouslySetInnerHTML={{ __html: dogData.dogDetail }}></p>
        </div>
      </div>
    </StyledContainer>
  );
};

export default History;
