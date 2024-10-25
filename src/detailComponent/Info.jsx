import React, { useContext, useState } from "react";
import { Typography, Button, Grid2, TextField } from "@mui/material";
import { Autocomplete } from "@mui/material";

import { StyledInfo } from "./StyledInfoSection";
import getTimeAgo from "./GetTImeAgo";
import { useLocation, useNavigate } from "react-router-dom";
import OffHeart from "@mui/icons-material/FavoriteBorderSharp";
import OnHeart from "@mui/icons-material/FavoriteSharp";
import AddCardIcon from "@mui/icons-material/AddCard";
import apiClient from "../token/AxiosConfig";
import { AuthContext } from "../token/AuthContext";

const DogInfo = ({ dogData }) => {
  const [isHeart, setIsHeart] = useState(dogData.isHeart);
  const [heartCount, setHeartCount] = useState(dogData.heart);

  const infoItems = dogData.regDate
    ? [
        {
          label: "등록시간",
          value: getTimeAgo(dogData.regDate),
          extra: `${dogData.regDate.slice(0, 10)}에 등록됨`,
        },
        { label: "참여자 수", value: `${dogData.fundMemberNum}` },
      ]
    : [];

  const categories = [dogData.species, dogData.gender, dogData.age]; // '종', '성별', '나이' 카테고리

  const WarningMessage = () => {
    return (
      <Typography
        variant="caption"
        className="flex"
        sx={{
          marginTop: 2,
          display: "block",
          color: "gray",
          borderRadius: "6px",
          backgroundColor: "#fef1f1",
          fontSize: "12px",
          padding: "5px 12px",
          lineHeight: "18px",
          textAlign: "start",
        }}
      >
        크라우드펀딩 투자는 <b>투자금액 전부</b>를 잃을 수 있는 <b>높은 위험</b>
        을 가지고 있습니다. 투자위험에 대해 이해가 있는 경우에만 투자에
        참여하세요.
      </Typography>
    );
  };

  const [inputValue, setInputValue] = useState(""); // 입력된 값 (항상 문자열)
  const [selectedOption, setSelectedOption] = useState(""); // 드롭다운에서 선택된 값 (항상 문자열)

  const priceOptions = ["10000", "20000", "30000", "직접 입력"]; // 드롭다운 옵션

  const { isAuthenticated } = useContext(AuthContext); // 인증 상태 가져오기
  const navigate = useNavigate();
  const location = useLocation();

  const handleSelectChange = (event, newValue) => {
    if (newValue === "직접 입력") {
      setSelectedOption("직접 입력"); // '직접 입력' 모드로 전환
      setInputValue(""); // 입력 필드 초기화
    } else if (newValue) {
      setSelectedOption(newValue); // 선택된 값 설정
      setInputValue(newValue); // 입력 필드에 값 설정
    } else {
      // newValue가 null인 경우 처리
      setSelectedOption("");
      setInputValue("");
    }
  };

  // 입력 값 변경 시 처리
  const handleInputChange = (event, newInputValue) => {
    if (selectedOption === "직접 입력") {
      // 숫자만 입력되도록 제한
      if (/^\d*$/.test(newInputValue)) {
        setInputValue(newInputValue);
      }
    } else {
      // '직접 입력'이 아닐 때는 입력 불가 (읽기 전용)
      setInputValue(selectedOption);
    }
  };

  const handleFundNow = () => {
    if (!inputValue || parseInt(inputValue, 10) <= 0) {
      alert("가격을 입력해 주세요."); // 알림 표시
      return;
    }

    const parsedPrice = parseInt(inputValue, 10);
    console.log(dogData.name);

    navigate("/Checkout", {
      state: {
        isFunding: true,
        dogId: dogData.dogId, 
        name: dogData.name,
        totalAmount: parsedPrice,
      },
    });
  };

  const handleHeartToggle = async () => {
    if (!isAuthenticated) {
      alert("로그인 후 이용할 수 있는 기능입니다.");
      navigate("/signIn", { state: { redirectedFrom: location.pathname } });
      return;
    }

    // 하트 상태를 토글하고 하트 수를 업데이트
    const newHeartState = isHeart === 1 ? 0 : 1;
    const newHeartCount = isHeart === 1 ? heartCount - 1 : heartCount + 1;

    setIsHeart(newHeartState);
    setHeartCount(newHeartCount);

    // 백엔드로 하트 상태 업데이트 요청
    try {
      const response = await apiClient.post("dog/addHeart", {
        dogId: dogData.dogId,
      });
      if (response.status !== 200) {
        // 실패 시 이전 상태로 복구
        setIsHeart(isHeart);
        setHeartCount(heartCount);
        alert("하트 업데이트에 실패했습니다.");
      }
    } catch (error) {
      // 오류 발생 시 이전 상태로 복구
      setIsHeart(isHeart);
      setHeartCount(heartCount);
      console.error(error);
      alert("하트 업데이트 중 오류가 발생했습니다.");
    }
  };

  return (
    <>
      <StyledInfo className="align-center">
        <h4 className="title">{dogData.title}</h4>

        {/* 이미지 영역 */}
        <div className="image-box">
          <img className="mainImage" src={dogData.mainImage} alt="mainImage" />
        </div>
        {/* 오른쪽 영역 */}
        <div className="right-section flex align-center">
          {/* 카테고리 텍스트 */}

          <div className="category-section flex flex-row">
            {categories.map((category, index) => (
              <span className="category" key={index}>
                {category}
              </span>
            ))}
          </div>
          {/* 펀딩 금액 */}
          <div className="fundInfo-section">
            <span className="fundingAmount">{dogData.fundCollection}원</span>
            <span className="flex text-small">펀딩중</span>

            {/* 달성률, 남은기간, 투자자수 등 */}
            <Grid2
              className="flex align-start w-full"
              container
              spacing={2}
              flexDirection="column"
              textAlign="start"
              sx={{ marginTop: 2 }}
            >
              {infoItems.map((item, index) => (
                <Grid2 className="flex flex-row" key={index} xs={12} sm={6}>
                  <Typography variant="body2">
                    {item.label}: <strong>{item.value}</strong>{" "}
                    {item.extra && `| ${item.extra}`}
                  </Typography>
                </Grid2>
              ))}
            </Grid2>
          </div>
          <div className="price-container">
            <Autocomplete
              className="w-full"
              freeSolo
              options={priceOptions}
              value={selectedOption}
              inputValue={inputValue}
              onChange={handleSelectChange}
              onInputChange={handleInputChange}
              openOnFocus
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="가격 선택 또는 입력"
                  placeholder="가격을 선택하거나 입력하세요"
                  slotProps={{
                    ...params.InputProps,
                    readOnly: selectedOption !== "직접 입력", // '직접 입력'일 때만 입력 가능
                    inputMode:
                      selectedOption === "직접 입력" ? "numeric" : "none",
                    pattern:
                      selectedOption === "직접 입력" ? "[0-9]*" : undefined,
                    onKeyPress: (event) => {
                      if (
                        selectedOption === "직접 입력" &&
                        !/[0-9]/.test(event.key)
                      ) {
                        event.preventDefault(); // 숫자가 아닌 입력 차단
                      }
                    },
                  }}
                />
              )}
            />
          </div>
          {/* 버튼들 */}
          <Grid2 sx={{ marginTop: 2 }} xs={12}>
            <Button
              variant={isHeart === 1 ? "contained" : "outlined"}
              sx={{ marginRight: 1 }}
              startIcon={isHeart === 1 ? <OnHeart /> : <OffHeart />}
              onClick={(e) => {
                e.stopPropagation(); // 부모 요소로 이벤트 전파 방지
                handleHeartToggle(); // 하트 업데이트 함수 호출
              }}
            >
              {heartCount}명이 관심있어요
            </Button>
            <Button
              variant="outlined"
              startIcon={<AddCardIcon />}
              onClick={handleFundNow}
            >
              결제하기
            </Button>
          </Grid2>

          {/* 경고 메시지 */}
          <WarningMessage />
        </div>
      </StyledInfo>
    </>
  );
};

export default DogInfo;
