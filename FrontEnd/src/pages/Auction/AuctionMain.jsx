import React, {useCallback, useEffect, useState} from "react";
import Grid from "@mui/material/Grid2";
import Container from "@mui/material/Container";
import AuctionCarousel from "../../components/Auction/AuctionCarousel";
import Button from "../../components/Auction/AuctionButton";
import apiClient from "../../token/AxiosConfig";
import AuctionWebSocket from "../../config/AuctionWebSocket"; // WebSocket 컴포넌트
import {useNavigate} from "react-router-dom";

const AuctionMain = () => {
  const navigate = useNavigate();
  const [auction, setAuction] = useState(null);
  const [remainingTime, setRemainingTime] = useState("");
  const [status, setStatus] = useState(0); // 0: 대기, 1: 진행 중, 2: 종료


  // 경매 상태 업데이트 API 호출
  const updateAuctionStatus = (auctionId, status) => {
    apiClient
      .post(`/auction/edit`, { auctionId, auctionStatus: status })
      .then(() => {
        if (status === 2) {
          fetchCurrentAuction();  // 경매 종료 시 다음 경매 데이터를 가져옴
        }
      })
      .catch((err) => {
        console.error("경매 상태 변경 실패:", err);
      });
  };

  // 남은 시간 계산 함수
  const calculateRemainingTime = useCallback((startTime, auctionId) => {
    const interval = setInterval(() => {
      const now = new Date();
      const start = new Date(startTime);
      const diff = start - now;

      if (diff > 0) {
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);
        setRemainingTime(`${hours}시간 ${minutes}분 ${seconds}초`);
      } else {
        setRemainingTime("경매 진행중");
        clearInterval(interval);
        if (auction?.auctionStatus === 0) {
          updateAuctionStatus(auctionId, 1);  // 경매 상태를 1로 업데이트 (진행 중)
        }
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [auction?.auctionStatus]);

  const fetchCurrentAuction = useCallback(() => {
    apiClient
      .get(`/auction/current`)  // 하나의 엔드포인트로 현재 또는 다음 경매를 가져옴
      .then((res) => {
        const auctionData = res.data;
        setAuction(auctionData);  // 경매 데이터 설정
        setStatus(auctionData.auctionStatus);  // 경매 상태 설정
  
        // 남은 시간 계산 (진행 중인 경매 또는 다음 경매)
        calculateRemainingTime(auctionData.startTime, auctionData.auctionId);
      })
      .catch((err) => {
        console.error("현재 경매 정보 가져오기 실패:", err);
      });
  }, [calculateRemainingTime]);
  
  // useEffect에서 fetchCurrentAuction을 사용
  useEffect(() => {
    fetchCurrentAuction();  // 페이지 로드 시 현재 또는 다음 경매 데이터를 가져옴
  }, [fetchCurrentAuction]);
  
  // WebSocket으로부터 경매 업데이트 받기
  const handleAuctionUpdate = useCallback(
    (data) => {
      if (data.auctionStatus === 1 || new Date(data.startTime) < new Date(auction.startTime)) {
        setAuction(data);  // WebSocket에서 받은 경매 데이터를 상태로 업데이트
        setStatus(data.auctionStatus);
        console.log("경매 바뀜 : " , auction)
        return auction;
      }
      if (data.auctionStatus === 2) {
        // 경매가 종료되었을 때 다음 경매 데이터를 가져옴
        fetchCurrentAuction(); // 현재 또는 다음 경매 데이터를 가져오는 함수
      }
    },
    [auction]
  );

  const handleEnterClick = () => {
    const currentTime = new Date();
    const auctionStartTime = new Date(auction.startTime);

    if (currentTime >= auctionStartTime) {
      // 입장 가능, 경매 시작
      console.log("경매 입장 성공");
      navigate("/auction/bid");
    } else {
      // 경매 시작 전이면 alert 메시지 출력
      alert("경매 시작 전입니다.");
    }
  };


  useEffect(() => {
    if (auction && auction.auctionStatus === 1) {
      console.log("경매 진행 중입니다.");
    }
  }, [auction]);

  useEffect(() => {
    if (auction) {
      console.log('경매 업데이트', auction);
    }
  }, [auction]);

  if (!auction) {
    return <div style={{marginTop:"400px", marginBottom:"400px"}}><span style={{fontSize:"30px", fontWeight:"bold"}}>진행 예정인 경매가 없습니다!</span></div>;
  }

  return (
    <>
      <Container style={{ marginTop: "200px" }}>
        <Grid container rowSpacing={10} columnSpacing={{ xs: 1, sm: 2, md: 3 }}>
          <Grid size={7} style={{ height: "400px" }}>
           <AuctionCarousel shopId={auction.shopId}/>
          </Grid>
          <Grid size={5}>
            <Grid container spacing={2}>
              <Grid size={12}>
                <div
                  style={{
                    marginTop: "10px",
                    fontSize: "35px",
                    fontWeight: "bold",
                  }}
                >
                  {remainingTime}
                </div>
              </Grid>
              <Grid size={12} style={{ marginTop: "30px" }}>
                <div>
                  <strong style={{ fontSize: "30px", fontWeight: "20px" }}>
                    {auction.shopName}
                  </strong>
                  <span style={{ marginLeft: "8px" }}>Jackpot사 제품</span>
                </div>
              </Grid>
            </Grid>
            <Grid container spacing={2}>
              <Grid size={12} style={{ marginTop: "50px" }}>
                <p style={{ fontsize: "15px" }}>{auction.shopDetail}</p>
              </Grid>
            </Grid>
            <Grid container spacing={2}>
              <Grid size={6} style={{ marginTop: "50px" }}>
                <p>경매 시작가</p>
              </Grid>
              <Grid size={6} style={{ marginTop: "50px" }}>
                <p>상품 가격</p>
              </Grid>
            </Grid>
            <Grid container spacing={2}>
              <Grid size={6}>
                <strong>{auction.startPrice}원</strong>
              </Grid>
              <Grid size={6}>
                <strong>{auction.shopPrice}원</strong>
              </Grid>
            </Grid>
          </Grid>
          <Grid size={6} style={{ height: "40px" }}>
            <Button text="뒤로가기" />
          </Grid>
          <Grid size={6}>
            {/*<Button text="입장하기"></Button>*/}
            <Button text="입장하기" onClick={handleEnterClick}/>
          </Grid>
          <Grid size={12}>
            <strong style={{ fontSize: "20px" }}>
              경매장은 Premium이상의 회원만 입장 가능합니다.
            </strong>
          </Grid>
        </Grid>
      </Container>
      {/* WebSocket 이벤트 리스너 설정 */}
      <AuctionWebSocket onAuctionUpdate={handleAuctionUpdate} />
    </>
  );
};

export default AuctionMain;