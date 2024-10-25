import React, { useState, Fragment, useContext } from "react";
import Box from "@mui/material/Box";
import AccountBoxIcon from "@mui/icons-material/AccountBox";
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";
import ListItemIcon from "@mui/material/ListItemIcon";
import Divider from "@mui/material/Divider";
import ShoppingCartIcon from "@mui/icons-material/ShoppingCart";
import Logout from "@mui/icons-material/Logout";
import Button from "@mui/material/Button";
import logo from "../../static/newLogoHorizontalOrange.png";
import { useNavigate } from "react-router-dom";
import { AuthContext } from "../../token/AuthContext";
import styled from "styled-components";
// import MypagePwModal from "../../myPage/MypagePwModal";

const LogoButton = styled.button`
  background-color: transparent;
  border: none;
  left: 200px;
  z-index: 100;
  align-self: center;
  width: 150px;
  margin: 10px;

  img {
    width: 100%;
    height: 4%;
    background-color: transparent;
  }
`;

export default function NavBar() {
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState(null);
  const { isAuthenticated, logout } = useContext(AuthContext);
  const open = Boolean(anchorEl);
  // const [isPwModalOpen, setIsPwModalOpen] = useState(false);

  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  // const handleMypageClick = () => {
  //   setIsPwModalOpen(true);
  // };

  // const handleCloseModal = () => {
  //   setIsPwModalOpen(false);
  // };

  return (
    <Fragment>
      <Box
        sx={{
          top: 0,
          left: 0,
          right: 0,
          position: "fixed", // 네비게이션 바를 고정
          width: "70%",
          borderRadius: "10px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          textAlign: "center",
          margin: "0 auto", // 가로 중앙으로 이동
          padding: "10px", // 버튼과의 간격 조정
          marginTop: "10px",
          zIndex: 1000, // 다른 요소들 위에 위치
        }}
      >
        <LogoButton
          className="flex align-center pointer"
          style={{ cursor: "pointer" }}
          onClick={() => navigate("/")}
        >
          <img className="flex " src={logo} alt="로고" />
        </LogoButton>

        <Box
          sx={{
            position: "absolute",
            borderRadius: "10px",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            bgcolor: "rgba(255, 255, 255);",
            boxShadow:
              "rgba(0, 0, 0, 0.1) 0rem 0.25rem 0.5rem -0.0625rem, rgba(0, 0, 0, 0.06) 0rem 0.125rem 0.25rem -0.0625rem",
          }}
        />

        <Box
          sx={{
            position: "absolute",
            borderRadius: "10px",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
          }}
        />
        <Box
          className=" align-center flex flex-row"
          sx={{
            justifyContent: "flex-end",
          }}
        >
          {/* <Button
            variant="text"
            style={{
              color: "black",
              fontSize: "18px",
              right: "1rem",
              top: "0.2rem",
            }}
            onClick={() => {
              navigate("/mypage");
            }}
          >
            마이페이지
          </Button> */}
          <Button
            variant="text"
            style={{
              color: "black",
              fontSize: "18px",
              right: "1rem",
              top: "0.2rem",
            }}
            onClick={() => {
              navigate("/dogList");
            }}
          >
            유기견펀딩
          </Button>

          <Button
            variant="text"
            style={{
              color: "black",
              fontSize: "18px",
              right: "1rem",
              top: "0.2rem",
            }}
            onClick={() => {
              navigate("/shop");
            }}
          >
            쇼핑몰
          </Button>

          <Button
            variant="text"
            style={{
              color: "black",
              fontSize: "18px",
              right: "1rem",
              top: "0.2rem",
            }}
            onClick={() => {
              navigate("/freeBoard");
            }}
          >
            게시판
          </Button>

          {isAuthenticated ? (
            <>
              <Button
                variant="contained"
                style={{
                  fontWeight: "bold",
                  backgroundColor: "black",
                  color: "white",
                }}
                onClick={handleClick} // 버튼 클릭 시 드롭다운 메뉴 열기
              >
                회원 메뉴
              </Button>

              <Menu
                anchorEl={anchorEl}
                id="account-menu"
                open={open}
                onClose={handleClose}
                onClick={handleClose}
                slotProps={{
                  paper: {
                    elevation: 0,
                    sx: {
                      overflow: "visible",
                      filter: "drop-shadow(0px 2px 8px rgba(0,0,0,0.32))",
                      mt: 1.5,
                    },
                  },
                }}
                transformOrigin={{ horizontal: "right", vertical: "top" }}
                anchorOrigin={{ horizontal: "right", vertical: "bottom" }}
              >
                <MenuItem
                  onClick={() => {
                    navigate("/mypage");
                    handleClose();
                  }}
                >
                  <ListItemIcon>
                    <AccountBoxIcon fontSize="small" />
                  </ListItemIcon>
                  내정보
                </MenuItem>
                <Divider />
                <MenuItem
                  onClick={() => {
                    logout(); // 로그아웃 처리
                    handleClose();
                  }}
                >
                  <ListItemIcon>
                    <ShoppingCartIcon fontSize="small" />
                  </ListItemIcon>
                  로그아웃
                </MenuItem>
              </Menu>
            </>
          ) : (
            <Button
              variant="contained"
              style={{
                fontWeight: "bold",
                backgroundColor: "#d64229",
              }}
              onClick={() => {
                navigate("/signIn");
              }}
            >
              로그인
            </Button>
          )}
        </Box>
      </Box>

      <Menu
        anchorEl={anchorEl}
        id="account-menu"
        open={open}
        onClose={handleClose}
        onClick={handleClose}
        slotProps={{
          paper: {
            elevation: 0,
            sx: {
              overflow: "visible",
              filter: "drop-shadow(0px 2px 8px rgba(0,0,0,0.32))",
              mt: 1.5,
              "& .MuiAvatar-root": {
                width: 32,
                height: 32,
                ml: -0.5,
                mr: 1,
              },
              "&::before": {
                content: '""',
                display: "block",
                position: "absolute",
                top: 0,
                right: 14,
                width: 10,
                height: 10,
                bgcolor: "background.paper",
                transform: "translateY(-25%) rotate(45deg)",
                zIndex: 0,
              },
            },
          },
        }}
        transformOrigin={{ horizontal: "right", vertical: "top" }}
        anchorOrigin={{ horizontal: "right", vertical: "bottom" }}
      >
        <MenuItem
          onClick={() => {
            // handleMypageClick();
            navigate("/mypage");
            handleClose();
          }}
        >
          <ListItemIcon>
            <AccountBoxIcon fontSize="small" />
          </ListItemIcon>
          마이페이지
        </MenuItem>
        <Divider />
        <MenuItem
          onClick={() => {
            logout(); // 로그아웃 처리
            handleClose();
          }}
        >
          <ListItemIcon>
            <Logout fontSize="small" />
          </ListItemIcon>
          로그아웃
        </MenuItem>
      </Menu>
      {/* <MypagePwModal open={isPwModalOpen} onClose={handleCloseModal} /> */}
    </Fragment>
  );
}
