import React, { useState } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Tabs,
  Tab,
} from "@mui/material";
import { useNavigate } from "react-router-dom";

import { findId, resetPassword } from "./memberAPI";
import { useEmailVerification } from "./EmailVerification";

const initialUserState = {
  phone: "",
  name: "",
  email: "",
  code: "",
  pwd: "",
  confirmPassword: "",
};

const TAB_FIND_ID = 0;
const TAB_RESET_PWD = 1;
const TAB_LABELS = ["아이디 찾기", "비밀번호 재설정"];

const EmailModal = ({ open, onClose, foundEmail, switchToResetPwdTab }) => (
  <Dialog
    open={open}
    onClose={(event, reason) => {
      if (reason !== "backdropClick" && reason !== "escapeKeyDown") {
        onClose();
      }
    }}
    maxWidth="xs"
    fullWidth
  >
    <DialogTitle>아이디 찾기 결과</DialogTitle>
    <DialogContent dividers>
      <p>가입하신 이메일은 다음과 같습니다:</p>
      <p style={{ fontWeight: "bold" }}>{foundEmail}</p>
    </DialogContent>
    <DialogActions>
      <Button onClick={onClose} color="primary" variant="contained">
        닫기
      </Button>
      <Button onClick={switchToResetPwdTab} variant="outlined" color="primary">
        비밀번호 재설정으로 이동
      </Button>
    </DialogActions>
  </Dialog>
);

const FindMember = () => {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [tabValue, setTabValue] = useState(TAB_FIND_ID);
  const [user, setUser] = useState(initialUserState);
  const [foundEmail, setFoundEmail] = useState("");
  const [showEmailModal, setShowEmailModal] = useState(false);
  const [duplicateMessage, setDuplicateMessage] = useState("");
  const [openSnackbar, setOpenSnackbar] = useState(false);

  const {
    sendVerificationCode,
    verifyCode,
    isEmailVerified,
    verificationCode,
    setVerificationCode,
  } = useEmailVerification(user.email, setDuplicateMessage, setOpenSnackbar);

  const resetStates = () => {
    setUser(initialUserState);
  };

  const openDialog = () => {
    setOpen(true);
    setTabValue(TAB_FIND_ID);
    resetStates();
  };

  const closeDialog = () => {
    setOpen(false);
    resetStates();
  };

  const handleChange = (e) => {
    setUser({ ...user, [e.target.name]: e.target.value });
  };

  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
    resetStates();
  };

  const switchToResetPwdTab = () => {
    setShowEmailModal(false);
    setTabValue(TAB_RESET_PWD);
    resetStates(); // 비밀번호 재설정으로 이동 시 상태 초기화
  };

  const handleFindId = async () => {
    try {
      const email = await findId(user);
      setFoundEmail(email);
      setShowEmailModal(true); // 모달 열기
    } catch (error) {
      alert("아이디를 찾을 수 없습니다.");
    }
  };

  const handleResetPassword = async () => {
    if (user.pwd !== user.confirmPassword) {
      alert("비밀번호가 일치하지 않습니다.");
      return;
    }
    try {
      const result = await resetPassword(user.email, user.pwd);

      if (result.success) {
        alert(result.message); // 성공 메시지
        navigate("/signIn");
        closeDialog();
      } else {
        alert(result.message); // 실패 메시지
      }
    } catch (error) {
      alert(error.message); // 네트워크 오류 또는 예외 처리
    }
  };

  return (
    <>
      <div className="assist">
        <Button
          onClick={(e) => {
            e.preventDefault();
            openDialog();
          }}
          style={{ visibility: open ? "hidden" : "visible" }} // 버튼이 열릴 때 감추기
          aria-hidden={open ? "true" : "false"} // 필요하다면 aria-hidden 제거 가능
          tabIndex={open ? -1 : 0} // 열릴 때 초점 제거
          inert={open ? "true" : undefined} // 요소를 비활성화
        >
          아이디 / 비밀번호 찾기
        </Button>
      </div>

      <div className="go-signUp" onClick={() => navigate("/signUp")}>
        회원이 아니신가요? <a>회원가입하기</a>
      </div>

      <Dialog
        open={open}
        onClose={(event, reason) => {
          if (reason !== "backdropClick" && reason !== "escapeKeyDown") {
            closeDialog(); // 닫기 버튼으로만 모달이 닫힘
          }
        }}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>{TAB_LABELS[tabValue]}</DialogTitle>
        <DialogContent dividers>
          <Tabs value={tabValue} onChange={handleTabChange} centered>
            {TAB_LABELS.map((label, index) => (
              <Tab key={index} label={label} />
            ))}
          </Tabs>

          {tabValue === TAB_FIND_ID && (
            <>
              <TextField
                margin="dense"
                label="이름"
                name="name"
                value={user.name}
                onChange={handleChange}
                fullWidth
              />
              <TextField
                margin="dense"
                label="전화번호"
                name="phone"
                value={user.phone}
                onChange={handleChange}
                fullWidth
              />
              <Button
                onClick={handleFindId}
                variant="contained"
                color="primary"
                fullWidth
                style={{ marginTop: "10px" }}
              >
                아이디 찾기
              </Button>
            </>
          )}

          {tabValue === TAB_RESET_PWD && (
            <>
              <TextField
                margin="dense"
                label="이름"
                name="name"
                value={user.name}
                onChange={handleChange}
                fullWidth
              />
              <TextField
                margin="dense"
                label="이메일"
                name="email"
                value={user.email}
                onChange={handleChange}
                fullWidth
                disabled={isEmailVerified}
              />
              {!isEmailVerified && (
                <Button
                  onClick={sendVerificationCode}
                  variant="contained"
                  color="primary"
                  fullWidth
                  style={{ marginTop: "10px" }}
                >
                  인증 코드 받기
                </Button>
              )}

              {isEmailVerified ? (
                <>
                  <TextField
                    margin="dense"
                    label="새 비밀번호"
                    name="pwd"
                    type="password"
                    value={user.pwd}
                    onChange={handleChange}
                    fullWidth
                  />
                  <TextField
                    margin="dense"
                    label="비밀번호 확인"
                    name="confirmPassword"
                    type="password"
                    value={user.confirmPassword}
                    onChange={handleChange}
                    fullWidth
                  />
                  <Button
                    onClick={handleResetPassword}
                    variant="contained"
                    color="primary"
                    fullWidth
                    style={{ marginTop: "10px" }}
                  >
                    비밀번호 변경
                  </Button>
                </>
              ) : (
                <>
                  <TextField
                    margin="dense"
                    label="인증 코드 입력"
                    name="verificationCode"
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value)}
                    fullWidth
                  />
                  <Button
                    onClick={verifyCode}
                    variant="contained"
                    color="primary"
                    fullWidth
                    style={{ marginTop: "10px" }}
                  >
                    인증 코드 확인
                  </Button>
                </>
              )}
            </>
          )}
        </DialogContent>

        <DialogActions>
          <Button onClick={closeDialog} color="primary">
            취소
          </Button>
        </DialogActions>
      </Dialog>

      <EmailModal
        open={showEmailModal}
        onClose={() => setShowEmailModal(false)}
        foundEmail={foundEmail}
        switchToResetPwdTab={switchToResetPwdTab}
      />
    </>
  );
};

export default FindMember;
