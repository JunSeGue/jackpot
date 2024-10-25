import React, { useState } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
} from "@mui/material";
import { styled } from "@mui/material/styles";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import apiClient from "../token/AxiosConfig";

// 스타일링 컴포넌트
const OrangeButton = styled(Button)({
  color: "#ff7600",
  backgroundColor: "transparent",
  border: "2px solid #ff7600",
  "&:hover": {
    backgroundColor: "#d64229",
    borderColor: "#d64229",
    color: "#ffffff",
  },
});

const OrangeTextField = styled(TextField)({
  "& .MuiInputLabel-root": {
    color: "#000000",
  },
  "& .MuiOutlinedInput-root": {
    "& fieldset": {
      borderColor: "#ff7600",
    },
    "&:hover fieldset": {
      borderColor: "#d64229",
    },
    "&.Mui-focused fieldset": {
      borderColor: "#ff7600",
    },
  },
});

const OrangeDialogTitle = styled(DialogTitle)({
  color: "#ff7600",
});

const OrangeDialog = styled(Dialog)({
  "& .MuiDialog-paper": {
    border: "2px solid #ff7600",
    borderRadius: "10px",
  },
});

const MypagePwModal = ({ open, onClose, onSuccess }) => {
  const [password, setPassword] = useState("");

  const handleConfirm = async () => {
    try {
      const { data, status } = await apiClient.get("member/checkPwd", {
        params: { pwd: password },
      });

      if (status === 200 && data) {
        onSuccess(); // 인증 성공 시 콜백 함수 호출
        onClose();   // 모달 닫기
      } else {
        alert("비밀번호가 틀립니다.");
      }
    } catch (error) {
      console.error("비밀번호 확인 오류:", error);
      alert("비밀번호 확인에 실패했습니다.");
    } finally {
      setPassword("");
    }
  };

  const handleClose = (event, reason) => {
    if (reason === "backdropClick" || reason === "escapeKeyDown") {
      return;
    }
    setPassword("");
    onClose();
  };

  return (
    <OrangeDialog open={open} onClose={handleClose}  disableEscapeKeyDown={true}
    disableEnforceFocus={false} // 이 부분 제거 또는 false로 설정
    aria-labelledby="modal-title"
    aria-describedby="modal-description" >
      <OrangeDialogTitle>
        <LockOutlinedIcon style={{ marginRight: "8px", marginTop: "8px", color: "#000000" }} />
        비밀번호 확인
      </OrangeDialogTitle>
      <DialogContent>
        <OrangeTextField
          autoFocus
          margin="dense"
          label="비밀번호"
          type="password"
          fullWidth
          variant="outlined"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </DialogContent>
      <DialogActions>
        <OrangeButton onClick={handleClose}>뒤로가기</OrangeButton>
        <OrangeButton onClick={handleConfirm}>확인</OrangeButton>
      </DialogActions>
    </OrangeDialog>
  );
};

export default MypagePwModal;
