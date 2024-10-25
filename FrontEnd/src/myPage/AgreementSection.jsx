import React from "react";
import styled from "styled-components";

const AgreementSectionWrapper = styled.div`
  margin-bottom: 20px;
  border: 1px solid #ccc;
  padding: 15px;
  text-align: left;
`;

const AgreementTitle = styled.h4`
  font-size: 1.5rem;
  margin-bottom: 30px;
  text-align: center;
`;

const AgreementText = styled.p`
  margin-bottom: 10px;
`;

const CheckboxWrapper = styled.div`
  margin-top: 20px;
`;

const AgreementSection = ({ isChecked, handleCheckboxChange }) => {
  return (
    <AgreementSectionWrapper>
      <AgreementTitle>회원 탈퇴 약관 동의서</AgreementTitle>
      <AgreementText>
        1. <strong>개인정보의 처리</strong>
      </AgreementText>
      <AgreementText>
        회원 탈퇴 시 귀하의 개인정보는 서비스 제공을 위해 수집된 정보 중 법적
        의무사항을 제외한 모든 정보가 삭제됩니다. 관련 법령에 따라 일부 정보는
        일정 기간 보관될 수 있습니다.
      </AgreementText>

      <AgreementText>
        2. <strong>탈퇴 후 데이터 복구 불가</strong>
      </AgreementText>
      <AgreementText>
        탈퇴 처리 완료 후 귀하의 계정 정보 및 이용 내역은 모두 삭제되며, 이후
        복구가 불가능합니다. 탈퇴 전 필요한 데이터를 백업하시기 바랍니다.
      </AgreementText>

      <AgreementText>
        3. <strong>재가입 및 제한 사항</strong>
      </AgreementText>
      <AgreementText>
        회원 탈퇴 후 동일한 이메일 주소로 재가입은 가능하나, 이전에 사용한
        데이터는 복구되지 않습니다.
      </AgreementText>

      <AgreementText>
        4. <strong>환불 및 결제</strong>
      </AgreementText>
      <AgreementText>
        탈퇴 후 환불이 필요한 경우, 탈퇴 전 고객센터에 별도로 문의해 주세요.
        탈퇴 완료 후에는 환불이 불가능합니다.
      </AgreementText>

      <AgreementText>
        5. <strong>문의</strong>
      </AgreementText>
      <AgreementText>
        회원 탈퇴와 관련하여 궁금한 사항이 있으시면 고객센터로 문의해 주시기
        바랍니다.
      </AgreementText>

      <CheckboxWrapper>
        <input
          type="checkbox"
          id="agreeTerms"
          checked={isChecked}
          onChange={handleCheckboxChange}
        />
        <label htmlFor="agreeTerms">
          위 내용을 모두 확인하였으며, 회원 탈퇴에 동의합니다.
        </label>
      </CheckboxWrapper>
    </AgreementSectionWrapper>
  );
};

export default AgreementSection;
