import {
  Card,
  CardActionArea,
  CardContent,
  CardMedia,
  Skeleton,
} from "@mui/material";
import React, { useState, useEffect } from "react";

import { useNavigate } from "react-router-dom";
import HeartButton from "./HeartButton";
import getTimeAgo from "../detailComponent/GetTImeAgo";
import styled from "styled-components";
import { ProgressBar } from "../myPage/ProgressBar";

const Dog = ({ dog, onHeartToggle = 0 }) => {
  const [checkImage, setCheckImage] = useState(false);
  const [thumbNail, setThumbNail] = useState("");

  const navigate = useNavigate();

  const categories = [dog.name, dog.species];

  useEffect(() => {
    if (dog.thumbNail) {
      setCheckImage(true);
      setThumbNail(dog.thumbNail);
    } else {
      setCheckImage(false);
      setThumbNail("");
    }
  }, [dog.thumbNail]);

  const handleDogDetail = () => {
    navigate(`/dog/${dog.dogId}`);
  };

  return (
    <StyledDogContainer className="flex flex-column justify-center">
      <Card
        onClick={handleDogDetail}
        sx={{ minWidth: "100%", position: "relative", paddingTop: "10px" }}
      >
        <CardActionArea
          sx={{
            zIndex: 0,
          }}
        >
          {checkImage ? (
            <CardMedia
              sx={{ height: 140, objectFit: "scale-down" }}
              component="img"
              image={thumbNail}
              loading="lazy"
            />
          ) : (
            <Skeleton
              animation="wave"
              variant="rectangular" // 직사각형 형태로 Skeleton을 설정
              sx={{
                width: "100%",
                height: 140,
                bgColor: "#bbbbbb", // 배경 색상이 적용됨
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
              }}
            ></Skeleton>
          )}
          <CardContent className="card-content flex flex-row justify-between">
            <h5 className="dogTitle">{dog.title}</h5>
            <ProgressBar value={dog.totalFund} />
            <div className="categories">
              {categories.map((category, index) => (
                <p key={index} className="category">
                  {category}
                </p>
              ))}
            </div>
            <div className="regDate-section">
              <span>{dog.regDate.slice(0, 10)}</span>
              <span className="getTime">{getTimeAgo(dog.regDate)}</span>
            </div>
          </CardContent>
        </CardActionArea>
        <HeartButton dog={dog} onHeartToggle={onHeartToggle} />
      </Card>
    </StyledDogContainer>
  );
};

export default Dog;

const StyledDogContainer = styled.div`
  .card-content {
    min-height: 100px;
    align-items: center;
    flex-wrap: wrap;
    > .dogTitle {
      font-size: 1.5rem;
      font-weight: bold;
      width: 100%;
      text-shadow: 1px 5px 3px rgba(0, 0, 0, 0.5);
    }
    > .categories {
      font-size: 1rem;
    }
  }
  .category {
    text-align: left;
  }
  .category:first-child {
    font-weight: bold;
    font-size: 1.2rem;
    white-space: normal;
    word-wrap: break-word;
  }
  .regDate-section {
    display: inline-flex;
    justify-content: flex-end;
    align-items: baseline;
    gap: 10px;
  }
  .getTime {
    font-weight: bold;
  }
`;
