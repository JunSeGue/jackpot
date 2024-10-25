import React from "react";
import styled from "styled-components";

const WarningSectionWrapper = styled.div`
  margin-bottom: 20px;
  border: 1px solid #ccc;
  padding: 15px;
  strong {
    color: ${(props) => props.theme.colors.red};
  }

  .warnning-text {
    color: red;
    font-weight: bold;
    margin-bottom: 20px;
    text-shadow: 1px 0 1px #333333;
  }
`;

const WarningTitle = styled.h4`
  font-size: 1.5rem;
  margin-bottom: 30px;
`;

const WarningList = styled.ul`
  list-style: disc;
  padding-left: 20px;
  > li {
    list-style: none;
    text-align: left;
    letter-spacing: -0.5px;
  }
`;

const WarningSection = () => {
  return (
    <WarningSectionWrapper>
      <WarningTitle>회원 탈퇴 안내</WarningTitle>
      <p className="warnning-text">
        회원 탈퇴를 진행하시기 전에 아래 사항을 꼭 확인해 주세요!
      </p>
      <WarningList>
        <li>
          <strong>회원 탈퇴</strong> 시 모든 개인정보 및 이용 내역이{" "}
          <strong>삭제</strong>됩니다.
        </li>
        <li>
          삭제된 정보는 복구가 <strong>불가능</strong>합니다.
        </li>
        <li>
          탈퇴 후 동일한 이메일로 <strong>재가입은 가능</strong>하지만, 이전
          데이터는 <strong>복구되지 않습니다</strong>.
        </li>
        <li>
          탈퇴와 동시에 이용 중인 서비스와 혜택은 <strong>모두 중지</strong>
          됩니다.
        </li>
      </WarningList>
    </WarningSectionWrapper>
  );
};

export default WarningSection;
