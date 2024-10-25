import { Button } from "@mui/material";
import React, { useState } from "react";
import styled from "styled-components";
import {
  validateEmail,
  validateName,
  validateNickname,
  validatePassword,
  validatePhoneNumber,
  formatPhoneNumber,
  getOnlyNumbers,
} from "../login/components/Validation";
import MypagePwModal from "./PwdModal";

import { checkNickName, editUser } from "./api";

const EditUserSection = ({ infoData }) => {
  const [formUser, setFormUser] = useState({
    ...infoData,
    phone: formatPhoneNumber(infoData.phone),
    pwd: "",
  });
  const [errors, setErrors] = useState({
    email: "",
    pwd: "",
    phone: "",
    name: "",
    nickName: "",
  });

  const [isEditing, setIsEditing] = useState(false); // 수정 모드 관리
  const [isModalOpen, setIsModalOpen] = useState(false); // 비밀번호 인증 모달 상태
  const [isPasswordVerified, setIsPasswordVerified] = useState(false); // 비밀번호 인증 상태
  const [nextAction, setNextAction] = useState(""); // 비밀번호 인증 후 다음 작업 지정

  // ------------------------
  // 1. 입력값 검증 및 상태 업데이트
  // ------------------------
  const handleChange = (e) => {
    const { name, value } = e.target;
    let error = "";
    let updatedValue = value;

    switch (name) {
      case "email":
        error = !validateEmail(value) ? "이메일 형식이 잘못되었습니다." : "";
        break;
      case "pwd":
        error = !validatePassword(value)
          ? "비밀번호는 8~20자 및 특수기호가 포함되어야 합니다."
          : "";
        break;
      case "phone":
        const numericValue = getOnlyNumbers(value);
        updatedValue = formatPhoneNumber(numericValue);
        error = !validatePhoneNumber(numericValue)
          ? "전화번호는 10~11자리 숫자만 허용됩니다."
          : "";
        break;
      case "name":
        error = !validateName(value)
          ? "이름은 한글 또는 영문만 가능합니다."
          : "";
        break;
      case "nickName":
        error = !validateNickname(value)
          ? "닉네임은 3~10자, 영문/한글/숫자만 허용됩니다."
          : "";
        break;
      default:
        break;
    }

    setErrors((prevErrors) => ({ ...prevErrors, [name]: error }));
    setFormUser((prevState) => ({ ...prevState, [name]: updatedValue }));
  };

  // ------------------------
  // 2. 수정 모드 처리 로직
  // ------------------------
  const handleEditMode = () => {
    if (!isPasswordVerified) {
      // 비밀번호 인증이 안 되어 있으면 모달 열기
      setNextAction("edit");
      setIsModalOpen(true);
    } else {
      // 인증 완료된 경우 수정 모드로 전환
      setIsEditing(true);
    }
  };

  const handleSave = async () => {
    // 수정 완료 후 저장 처리
    setIsEditing(false);

    const dataToSend = {
      ...formUser,
      phone: getOnlyNumbers(formUser.phone), // 전화번호에서 숫자만 추출
    };

    try {
      await editUser(dataToSend); // API 호출로 회원정보 수정
    } catch (error) {
      console.error("Error updating member:", error);
    }
  };

  const handleCancelEdit = () => {
    // 수정 취소 처리
    setIsEditing(false);
    setFormUser({
      ...infoData,
      phone: formatPhoneNumber(infoData.phone),
      pwd: "", // 비밀번호는 별도 처리
    });
    setErrors({
      email: "",
      pwd: "",
      phone: "",
      name: "",
      nickName: "",
    });
  };

  const handlePasswordSuccess = () => {
    // 비밀번호 인증 성공 시 처리
    setIsPasswordVerified(true);
    setIsModalOpen(false);

    if (nextAction === "edit") {
      setIsEditing(true); // 수정 모드로 전환
    }
  };

  // ------------------------
  // 4. 닉네임 중복 확인 로직
  // ------------------------
  const handleNicknameCheck = async () => {
    try {
      await checkNickName(formUser.nickName); // 닉네임 중복 확인 API 호출
    } catch (error) {
      console.error("Error checking nickname:", error);
    }
  };

  // ------------------------
  // 5. 입력 필드 및 버튼 렌더링
  // ------------------------
  const input = [
    { label: "이메일", name: "email", type: "text", readOnly: true },
    {
      label: "비밀번호",
      name: "pwd",
      type: "password",
      placeholder: "비밀번호 수정",
    },
    {
      label: "전화번호",
      name: "phone",
      type: "text",
      placeholder: "전화번호 수정",
    },
    { label: "이름", name: "name", type: "text", placeholder: "이름 수정" },
    {
      label: "닉네임",
      name: "nickName",
      type: "text",
      placeholder: "새로운 닉네임 입력",
      withCheck: true,
    },
  ];

  return (
    <StyledEditMember className="flex flex-column">
      <h4 className="edit-title text-left p-2 w-full">회원정보 수정</h4>
      <form onSubmit={(e) => e.preventDefault()}>
        {input.map((field, index) => (
          <div className="section-input flex flex-row" key={index}>
            <span className="input-title">{field.label}:</span>
            <input
              type={field.type}
              name={field.name}
              placeholder={field.placeholder}
              value={formUser[field.name]}
              onChange={handleChange}
              readOnly={field.readOnly || !isEditing} // 수정 모드 여부에 따라 활성화
              className="input-text"
            />
            {errors[field.name] && (
              <p style={{ color: "red" }}>{errors[field.name]}</p>
            )}
            {field.withCheck && isEditing && (
              <Button onClick={handleNicknameCheck} color="primary">
                닉네임 중복검사
              </Button>
            )}
          </div>
        ))}

        <div className="flex justify-end">
          {isEditing ? (
            <>
              <Button onClick={handleCancelEdit} color="primary">
                취소하기
              </Button>
              <Button onClick={handleSave} color="primary">
                저장하기
              </Button>
            </>
          ) : (
            <>
              <Button onClick={handleEditMode} color="primary">
                수정하기
              </Button>
            </>
          )}
        </div>
      </form>
      <MypagePwModal
        open={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={handlePasswordSuccess}
      />
    </StyledEditMember>
  );
};

export default EditUserSection;

const StyledEditMember = styled.div`
  h4 {
    font-size: 1.8rem;
  }
  .section-input {
    width: 100%;
    margin-bottom: 30px;
    > .input-title {
      width: 15%;
    }
    > .input-text {
      border: 1px solid ${(props) => props.theme.colors.pastelOrange};
      padding: 8px;
      border-radius: 4px;
      flex-grow: 1;
    }
  }
`;
