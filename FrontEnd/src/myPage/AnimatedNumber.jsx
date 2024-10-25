import React, { useEffect, useState } from 'react';
import styled from 'styled-components';

const AnimatedNumber = ({ value, duration = 2000 }) => {
  // 랜덤한 초기값 설정
  const [displayValue, setDisplayValue] = useState(Math.floor(Math.random() * value));

  useEffect(() => {
    const totalSteps = duration / 10; // 전체 스텝 수
    const increment = (value - displayValue) / totalSteps; // 현재값에서 목표값까지의 증가분 계산

    let currentValue = displayValue;
    
    const interval = setInterval(() => {
      currentValue += increment;

      // 목표값에 도달하면 정지
      if (currentValue >= value) {
        currentValue = value;
        clearInterval(interval);
      }

      setDisplayValue(Math.round(currentValue));
    }, 10);

    return () => clearInterval(interval); // 컴포넌트 언마운트 시 setInterval 해제
  }, [value, duration]);

  return <StyledAnimatedSpan>{displayValue}</StyledAnimatedSpan>;
};

export default AnimatedNumber;

// styled-components로 애니메이션 추가
const StyledAnimatedSpan = styled.span`
  display: inline-block;
  animation: bounce 0.5s ease-out;

  @keyframes bounce {
    0% {
      transform: translateY(0);
      opacity: 0.8;
    }
    50% {
      transform: translateY(-10px);
      opacity: 1;
    }
    100% {
      transform: translateY(0);
      opacity: 0.8;
    }
  }
`;
