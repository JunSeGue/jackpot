import React, { useState, useContext } from "react";
import styled from "styled-components";

import { useLocation, useNavigate } from "react-router-dom";
import OffHeart from "@mui/icons-material/FavoriteBorderSharp";
import OnHeart from "@mui/icons-material/FavoriteSharp";
import theme from "../config/theme";
import apiClient from "../token/AxiosConfig";

import { AuthContext } from "../token/AuthContext";

const StyledIconButton = styled.button`
  position: absolute;
  top: 8px;
  right: 8px;
  color: ${(props) =>
    props.$heart === 1 ? theme.colors.red : theme.colors.gray};
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  outline: none;
  box-shadow: none;
  z-index: 10;
  &:hover {
    background-color: transparent;
  }
  &:focus {
    outline: none;
  }
  .heart {
    color: ${(props) => props.theme.colors.red};
  }
`;

const HeartButton = (props) => {
  const { onHeartToggle, dog } = props;
  const [isHeart, setIsHeart] = useState(props.dog.isHeart);
  const { isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();
  const location = useLocation();

  const handleHeartToggle = () => {
    setIsHeart((prevHeart) => (prevHeart === 1 ? 0 : 1));
  };
  /* heart db추가 api 성공 시 던져주면 그거 */
  const apiHeartUpdate = async () => {
    try {
      const response = await apiClient.post("dog/addHeart", {
        dogId: dog.dogId,
      });
      if (onHeartToggle) {
        onHeartToggle();
        alert(
          isHeart === 0
            ? `${dog.name} 하트를 눌렀습니다.`
            : `${dog.name} 하트를 취소하였습니다.`
        );
      }

      if (response.status === 200) {
        console.log("Heart Update Success");
      } else {
        setIsHeart((prevHeart) => (prevHeart === 1 ? 0 : 1));
      }
    } catch (error) {
      console.error(error);
      setIsHeart((prevHeart) => (prevHeart === 1 ? 0 : 1));
    }
  };

  const updateHeart = () => {
    if (!isAuthenticated) {
      alert("로그인 후 이용할 수 있는 기능입니다.");
      navigate("/signIn", { state: { redirectedFrom: location.pathname } });
    } else {
      handleHeartToggle();
      apiHeartUpdate();
    }
  };

  return (
    <StyledIconButton
      $heart={isHeart}
      onClick={(e) => {
        e.stopPropagation(); // 부모 요소로 이벤트 전파 방지
        updateHeart();
      }}
    >
      {isHeart === 1 ? <OnHeart /> : <OffHeart />}
      <div className="heart">{dog.heart}</div>
    </StyledIconButton>
  );
};

export default HeartButton;
