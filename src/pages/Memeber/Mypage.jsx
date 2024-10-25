import React, { useEffect, useState } from "react";

import {
  StyledMypageWrapper,
  StyeldRightSection,
  StyledMypageSection,
} from "../../myPage/Mypage.styles";

import { MockShopData } from "../../myPage/MockMypageData";

import Grid2 from "@mui/material/Grid2";
import { Avatar, CardContent, Divider, Typography } from "@mui/material";
import MypageSideBar from "../../myPage/MyPageSideBar";

import apiClient from "../../token/AxiosConfig";
import InquirySection from "../../myPage/InquirySection";
import PurchaseHistorySection from "../../myPage/ShopPurchaseSection";
import EditUserSection from "../../myPage/EditUserSection";
import { FundHistorySection } from "../../myPage/FundHisorySection";
import { formatPhoneNumber } from "../../login/components/Validation";
import MypagePwModal from "../../myPage/PwdModal";
import DeleteAccount from "../../myPage/DeleteAccount";

const Mypage = () => {
  const [currentPage, setCurrentPage] = useState("all");

  const [infoData, setInfoData] = useState({
    memberId: "",
    name: "",
    email: "",
    phone: "",
    grade: "",
    newGrade: "기본 회원",
  });

  const [shopData, setShopData] = useState([]);
  const [showAll, setShowAll] = useState({
    purchase: false,
    inquiry: false,
    funding: false,
  });

  const [isModalOpen, setIsModalOpen] = useState(false); // 모달 열림 상태
  const [targetPage, setTargetPage] = useState("all"); // 이동할 페이지
  const [isPasswordVerified, setIsPasswordVerified] = useState(false); // 비밀번호 인증 상태

  useEffect(() => {
    const apiInfo = async () => {
      try {
        const response = await apiClient.get("member/myPage");
        console.log(response.data);

        // 가져온 데이터를 기반으로 grade를 판별해서 상태 업데이트
        const updatedData = {
          ...response.data,
          newGrade: response.data.grade === 1 ? "기본 회원" : "VIP",
        };
        setInfoData(updatedData);
      } catch (error) {
        console.log(error);
      }
    };
    // const apiShopData = async () => {
    //   try {
    //     const response = await apiClient.get("order/findAll", {
    //       params: {
    //         memberId: infoData.memberId,
    //       },
    //     });

    //     setShopData(response.data);
    //   } catch (error) {
    //     console.log(error);
    //   }
    // };

    apiInfo();
    // apiShopData();
  }, []);

  useEffect(() => {
    const mockShopData = () => {
      const response = MockShopData;
      console.log(response.data);
      setShopData(response.data);
    };

    mockShopData();
  }, []);

  // section 조건 변경에 따른 렌더링 함수
  const handleSectionChange = (section) => {
    if (section === "info") {
      setTargetPage(section);
      if (!isPasswordVerified) {
        setIsModalOpen(true); // 인증 모달 열기
      } else {
        setCurrentPage(section); // 이미 인증된 경우 바로 페이지 변경
      }
    } else {
      setCurrentPage(section);
      if (section === "all") {
        setShowAll({
          purchase: false,
          inquiry: false,
          funding: false,
        });
      } else {
        setShowAll({
          purchase: false,
          inquiry: false,
          funding: false,
          [section]: true,
        });
      }
    }
  };

  const handlePasswordSuccess = () => {
    setIsPasswordVerified(true);
    setIsModalOpen(false); // 모달 닫기
    setCurrentPage(targetPage); // 인증 성공 후 targetPage로 이동
  };

  const renderAllContent = () => (
    <>
      <InfoSection infoData={infoData} />
      <FundHistorySection showAll={showAll[currentPage]} />
      <PurchaseHistorySection
        shopData={shopData}
        showAll={showAll[currentPage]}
      />
      <InquirySection showAll={showAll[currentPage]} />

      {/* <DogProfile/> */}
    </>
  );

  const renderSingleContent = () => {
    switch (currentPage) {
      case "info":
        return <EditUserSection infoData={infoData} />;
      case "funding":
        return <FundHistorySection showAll={showAll[currentPage]} />;
      case "purchase":
        return (
          <PurchaseHistorySection
            shopData={shopData}
            showAll={showAll[currentPage]}
          />
        );
      case "inquiry":
        return <InquirySection showAll={showAll[currentPage]} />;
      case "deleteUser":
        return <DeleteAccount />;

      default:
        return renderAllContent(); // 기본적으로 모든 섹션 렌더링
    }
  };

  // ---------------------------------------------------------------------

  const InfoSection = () => {
    return (
      <StyledMypageSection className="w-full">
        <h4 className="text-left p-0 m-0">프로필</h4>

        <div className="section-mypage flex flex-row">
          {/* Left Section */}

          <Grid2
            onClick={handleMypage}
            sx={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              padding: 5,
              backgroundColor: "#f5f5f5",
              borderRadius: ".5rem 0 0 .5rem",
            }}
          >
            <Avatar
              src="https://static.nid.naver.com/images/web/user/default.png"
              sx={{ width: 100, height: 100, mb: 2 }}
            />
            <Typography variant="h5">{infoData.name}</Typography>
            <Typography variant="body2">Gold</Typography>
          </Grid2>

          {/* Right Section */}

          <CardContent className="w-full">
            <Typography variant="h6">Information</Typography>
            <Divider sx={{ my: 2 }} />
            <ul className="flex justify-around">
              <li key="email">
                <h3 className="info-title">Email</h3>
                <span>{infoData.email}</span>
              </li>
              <li key="phone">
                <h3 className="info-title">Phone</h3>
                <span>{formatPhoneNumber(infoData.phone)}</span>
              </li>

              <li key="nickName">
                <h3 className="info-title">닉네임</h3>
                <span>{infoData.nickName}</span>
              </li>
              <li key="address">
                <h3 className="info-title">{infoData.address}</h3>
                <span>집 주소</span>
              </li>
            </ul>
          </CardContent>
        </div>
      </StyledMypageSection>
    );
  };

  const handleMypage = (e) => {
    e.preventDefault();
    // 조건이 눌렸을 경우 개인정보 수정 창이 떠야한다.
  };

  return (
    <>
      <div className="container flex justify-center">
        <StyledMypageWrapper className="flex flex-row">
          {/* leftSection */}
          <MypageSideBar
            infoData={infoData}
            currentPage={currentPage}
            handleSectionChange={handleSectionChange}
          />
          {/* RightSection */}
          <StyeldRightSection className="right-section flex flex-column  w-full ">
            {currentPage === "all" ? renderAllContent() : renderSingleContent()}
          </StyeldRightSection>
        </StyledMypageWrapper>
        <MypagePwModal
          open={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          onSuccess={handlePasswordSuccess}
        />
      </div>
    </>
  );
};
export default Mypage;

export const NoneContent = () => {
  return <p className="section-noneContent ">정보가 없습니다.</p>;
};
