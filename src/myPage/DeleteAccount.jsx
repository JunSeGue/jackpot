import React, { useState } from "react";
import styled from "styled-components";
import WarningSection from "./WarningSection";
import AgreementSection from "./AgreementSection";
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
} from "@mui/material"; // MUI의 Button을 사용
import MypagePwModal from "./PwdModal"; // 비밀번호 인증 모달
import { deleteUser } from "./api";

const DeleteAccountContainer = styled.div`
  padding: 20px;
  border: 1px solid #3333;
`;

const Title = styled.h2`
  font-size: 2rem;
  margin-bottom: 20px;
`;

const DeleteAccount = () => {
  const [isChecked, setIsChecked] = useState(false); // 약관 동의 상태
  const [isDialogOpen, setIsDialogOpen] = useState(false); // 탈퇴 확인 모달 상태
  const [isModalOpen, setIsModalOpen] = useState(false); // 비밀번호 인증 모달 상태
  const [isPasswordVerified, setIsPasswordVerified] = useState(false); // 비밀번호 인증 상태

  const handleCheckboxChange = (e) => {
    setIsChecked(e.target.checked);
  };

  const handleDeleteAccount = () => {
    if (isChecked) {
      setIsDialogOpen(true); // 탈퇴 확인 모달창 열기
    } else {
      alert("회원 탈퇴 약관에 동의해 주세요.");
    }
  };

  const handleCloseDialog = () => {
    setIsDialogOpen(false); // 탈퇴 확인 모달창 닫기
  };

  const handleConfirmDelete = () => {
    setIsDialogOpen(false);
    setIsModalOpen(true); // 비밀번호 인증 모달 열기
  };

  const handlePasswordSuccess = () => {
    setIsPasswordVerified(true);
    deleteUser();
    setIsModalOpen(false);
    alert(
      isPasswordVerified
        ? "회원 탈퇴가 완료되었습니다."
        : "비밀번호가 일치하지 않습니다. 다시 시도해 주세요."
    ); // 실제 탈퇴 로직을 여기에 추가
  };

  const ConfirmModal = () => (
    <Dialog
      open={isDialogOpen}
      onClose={handleCloseDialog}
      aria-labelledby="alert-dialog-title"
      aria-describedby="alert-dialog-description"
    >
      <DialogTitle id="alert-dialog-title">회원 탈퇴 확인</DialogTitle>
      <DialogContent>
        <DialogContentText id="alert-dialog-description">
          정말로 탈퇴하시겠습니까? 이 작업은 되돌릴 수 없습니다.
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCloseDialog} color="primary">
          아니오
        </Button>
        <Button onClick={handleConfirmDelete} color="error" autoFocus>
          예
        </Button>
      </DialogActions>
    </Dialog>
  );

  return (
    <DeleteAccountContainer>
      <Title>회원 탈퇴 안내 및 약관 동의</Title>

      {/* 회원 탈퇴 경고문 */}
      <WarningSection />

      {/* 회원 탈퇴 약관 동의서 */}
      <AgreementSection
        isChecked={isChecked}
        handleCheckboxChange={handleCheckboxChange}
      />

      {/* MUI Button 사용 */}
      <Button
        onClick={handleDeleteAccount}
        variant="contained"
        color="error"
        disabled={!isChecked}
        style={{ marginTop: "20px" }}
        fullWidth
      >
        회원 탈퇴
      </Button>

      {/* 탈퇴 확인 모달 */}
      <ConfirmModal />

      {/* 비밀번호 인증 모달 */}
      <MypagePwModal
        open={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={handlePasswordSuccess} // 비밀번호 인증 성공 시 탈퇴 처리
      />
    </DeleteAccountContainer>
  );
};

export default DeleteAccount;
