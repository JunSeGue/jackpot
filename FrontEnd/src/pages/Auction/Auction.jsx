import React, {useState, useEffect, useCallback} from "react";
import AuctionWebSocket from "../../config/AuctionWebSocket";
import Grid from "@mui/material/Grid2";
import Container from "@mui/material/Container";
import Typography from "@mui/material/Typography";
import Stack from '@mui/material/Stack';
import AuctionCarousel from "../../components/Auction/AuctionCarousel";
import Button from "../../components/Auction/AuctionButton";
import styled from "styled-components";
import apiClient from "../../token/AxiosConfig";
import {useNavigate} from "react-router-dom";

const Auction = () => {
    const navigate = useNavigate();
    const [auction, setAuction] = useState([]);
    const [bidPrice, setBidPrice] = useState(0);
    const [highestBidPrice, setHighestBidPrice] = useState(0); // 현재 최고 입찰가
    const [user, setUser] = useState([]);
    const [timeLeft, setTimeLeft] = useState(60); // 초기 남은 시간: 240초 (4분)
    const [isAuctionEnded, setIsAuctionEnded] = useState(false); // 경매 종료 상태
    const biddingData = {
        bidPrice: bidPrice,
        bidTime: new Date().toISOString(),
        memberID: user.memberID,
        memberName: user.name,
        auctionId: auction.auctionId,
        shopId: auction.shopId
    };

    const addBid = () => {
        setBidPrice(prevPrice => prevPrice + 1000);
        console.log(bidPrice);
    };

    const subtractBid = () => {
        setBidPrice(prevPrice => {
            return prevPrice > auction.startPrice ? prevPrice - 1000 : auction.startPrice;
        });
    };
    const highestBid = useCallback(() => {
        apiClient.get(`/bid/highest`)
            .then((res) => {
                if (res.data === 0) {
                    setHighestBidPrice(auction.startPrice); // 경매 시작가 설정
                }
                console.log("최고 입찰가 : " + res.data);
                setHighestBidPrice(res.data);
                setBidPrice(res.data);
            })
            .catch((err) => {
                console.error("로드 실패:", err);
            });
    }, [auction.startPrice]);  // auction.startPrice가 변경될 때만 함수가 재정의됨
    const registerBid = () => {
        console.log(biddingData);
        if (bidPrice > highestBidPrice) {
            setHighestBidPrice(bidPrice); // 최고 입찰가 업데이트
            apiClient.post(`/bid/register`, biddingData)
                .then((res) => {

                })
                .catch((err) => {
                    console.error("입찰 실패:", err);
                });
        } else {
            alert("현재 입찰가가 최고 입찰가보다 높아야 합니다.");
        }
    };
    const handleAuctionUpdate = useCallback(
        (data) => {
            if (data.auctionStatus === 1 || new Date(data.startTime) < new Date(auction.startTime)) {
                setAuction(data);  // WebSocket에서 받은 경매 데이터를 상태로 업데이트
                setHighestBidPrice(auction.startPrice);
                console.log("경매 바뀜 : " , auction)
                return auction;
            }
            if (data.auctionStatus === 2) {
                // 경매가 종료되었을 때 다음 경매 데이터를 가져옴
                navigate('/auction') // 현재 또는 다음 경매 데이터를 가져오는 함수
            }
        },
        [auction]
    );
    const fetchCurrentAuction = useCallback(() => {
        apiClient
            .get(`/auction/current`)  // 하나의 엔드포인트로 현재 또는 다음 경매를 가져옴
            .then((res) => {
                const auctionData = res.data;
                console.log(auctionData);
                setAuction(auctionData);  // 경매 데이터 설정
            })
            .catch((err) => {
                console.error("현재 경매 정보 가져오기 실패:", err);
            });
    }, []);

    const fetchUserInfo = async () => {
        try {
            const response = await apiClient.get("/member/myPage");
            console.log(response.data);
            setUser(response.data);
        } catch (error) {
            console.error("Error fetching user info:", error);
        }
    };

    const handleBidUpdate = (bidData) => {
        console.log("소켓에서 받은 입찰 정보: " + bidData.bidPrice);
        setHighestBidPrice(bidData.bidPrice);  // 웹소켓으로 받은 입찰가를 최고가로 설정
        setBidPrice(bidData.bidPrice);  // 현재 입찰가도 업데이트
        console.log("high: " + highestBidPrice)
        console.log("bid: " + bidPrice)
    };

    const handleTimerUpdate = (newTimeLeft) => {
        setTimeLeft(newTimeLeft); // 남은 시간 업데이트
        // console.log(timeLeft);
    };

    const handleAuctionEnd = useCallback((data) => {
        console.log("경매 종료 이벤트 수신:", data);
        setAuction(prevAuction => ({ ...prevAuction, auctionStatus: 2 }));
        setIsAuctionEnded(true); // 경매 종료 상태로 설정
        endAuction();
    }, []);

    const handleLastBidder = (winner) => {
        console.log(`경매 종료, 낙찰자는 ${winner}`);
        if (winner === user.name) {
            const proceedToPayment = window.confirm("낙찰 되셨습니다! 결재창으로 이동 하시겠습니까? 취소를 할시 낙찰이 취소됩니다.");
            if (proceedToPayment) {
                // 결제 페이지로 리디렉션
                navigate("/Checkout",{
                    state:{
                        isFunding: false,
                        productNames: [{
                            shopId : auction.shopId,
                            name: auction.shopName,
                            productPrice: highestBidPrice,
                            quantity:1,
                            totalAmount: highestBidPrice
                        }],
                       totalAmount: highestBidPrice
                    }
                }) // 결제 페이지로 이동하는 코드 추가
            }
        } else {
            alert(`경매 종료! 낙찰자는 ${winner}입니다.`);
            navigate('/auction');
        }
    };

    const endAuction = useCallback(() => {
        // if (isAuctionEnded) {
        //     console.log("경매 종료 API가 이미 호출되었습니다.");  // 이미 종료된 경매 처리 방지
        //     return;
        // }
        if (auction.auctionStatus === 2) {
            console.log("경매가 이미 종료되었습니다.");  // 경매가 이미 종료된 경우 더 이상 요청을 보내지 않음
            console.log("종료: auction" + auction);
            return;
        }
        apiClient.get('/bid/end')  // 경매 종료 API 호출
            .then(() => {
                console.log("경매 종료 API 호출 완료");
                // 입찰 테이블의 데이터를 삭제 (필요에 따라 API 호출)
                apiClient.delete(`/bid/remove?auctionId=${auction.auctionId}&memberID=${user.memberID}`)
                    .then(() => {
                        console.log("입찰 데이터 삭제 완료");
                    })
                    .catch((err) => {
                        console.log("입찰 데이터 삭제 실패:", err);
                    });
            })
            .catch((err) => {
                console.error("경매 종료 API 호출 실패:", err);
            });
    }, [auction.auctionId, auction.auctionStatus, user.memberID]);  // 의존성 배열 추가


        useEffect(() => {
            if (timeLeft === 0 && auction.auctionStatus !== 2) {
                endAuction(); // 타이머가 0이 되었을 때 경매 종료 함수 호출
            }
        }, [timeLeft, endAuction, auction.auctionStatus]);

        // useEffect에서 fetchCurrentAuction을 사용
        useEffect(() => {
            fetchCurrentAuction();  // 페이지 로드 시 현재 또는 다음 경매 데이터를 가져옴
            fetchUserInfo();
            highestBid();
        }, [fetchCurrentAuction, auction.auctionStatus, highestBid]);

        return (
            <>
                <AuctionWebSocket  onTimerUpdate={handleTimerUpdate}
                                   onBidUpdate={handleBidUpdate}
                                   onAuctionEnd={handleAuctionEnd}
                                   onLastBidder={handleLastBidder}
                                   onAuctionUpdate={handleAuctionUpdate}
                /> {/* 실시간 입찰 업데이트 처리 */}
                <Container>
                    <Grid container spacing={6} columns={16} style={{marginTop: "200px", height: "600px"}}>
                        <Grid size={9}>
                            <AuctionCarousel style={{height: "100%"}} shopId={auction.shopId}/>
                            <Typography variant="h6" component="h2">{auction.shopDetail}</Typography>
                        </Grid>
                        <Grid size={7}>
                            <Stack spacing={4}>
                                <Stack spacing={2}>
                                    <Typography variant="h4">낙찰까지 남은 시간</Typography>
                                    <Typography variant="h4">
                                        {Math.floor(timeLeft / 60)}:{(timeLeft % 60).toString().padStart(2, '0')}
                                    </Typography> {/* 남은 시간을 분:초 형식으로 표시 */}
                                </Stack>
                                <Stack>
                                    <Typography variant="h6"><span style={{
                                        marginLeft: "200px",
                                        marginTop: "500px",
                                        paddingTop: "100px",
                                        fontSize: "16px"
                                    }}>상품 가격</span></Typography>
                                    <Typography variant="bod2"><span style={{
                                        marginLeft: "150px",
                                        fontSize: "25px",
                                        fontWeight: "bold"
                                    }}>{auction.shopPrice}원</span></Typography>
                                </Stack>
                                <Stack>
                                    <Typography variant="h6"><span style={{
                                        marginLeft: "190px",
                                        marginTop: "500px",
                                        paddingTop: "100px",
                                        fontSize: "16px"
                                    }}>경매 시작가</span></Typography>
                                    <Typography variant="bod2"><span style={{
                                        marginLeft: "210px",
                                        fontSize: "25px",
                                        fontWeight: "bold"
                                    }}>{auction.startPrice}원</span></Typography>
                                </Stack>
                                <Stack>
                                    <Typography variant="h6"><span style={{
                                        marginLeft: "160px",
                                        marginTop: "500px",
                                        paddingTop: "100px",
                                        fontSize: "16px"
                                    }}>현재 최고 입찰가</span></Typography>
                                    <Typography variant="body2"><span style={{
                                        marginLeft: "200px",
                                        fontSize: "25px",
                                        fontWeight: "bold"
                                    }}>{highestBidPrice}원</span></Typography>
                                </Stack>
                                <Stack direction="row" alignItems="center" justifyContent="center" spacing={2}
                                       style={{marginRight: "80px", marginTop: "60px"}}>
                                    <StyledWrapper>
                                        <button className="download" onClick={subtractBid}>
                                            -
                                            <span className="tooltip">-1,000￦</span>
                                        </button>
                                    </StyledWrapper>
                                    <label>
                                        <input value={bidPrice} style={{color: 'B7B7B7', background: "#B7B7B7"}}
                                               readOnly></input>
                                    </label>
                                    <StyledWrapper>
                                        <button className="download" onClick={addBid}>
                                            +
                                            <span className="tooltip">+1,000￦</span>
                                        </button>
                                    </StyledWrapper>
                                </Stack>
                            </Stack>
                        </Grid>
                    </Grid>
                </Container>
                <Container>
                    <Grid container spacing={6} columns={16}>
                        <Grid size={8}><Button text="나가기"/></Grid>
                        <Grid size={8}>
                            <Button text="입찰하기" onClick={registerBid}/>
                        </Grid>
                    </Grid>
                </Container>
            </>
        );
    };


const StyledWrapper = styled.div`
  .download {
    width: 40px;
    height: 40px;
    background: none;
    border: 0;
    box-sizing: border-box;
    margin: 1em;
    //padding: 1em 2em;
    color: black;
    font-size: 20px;
    font-weight: 700;
    position: relative;
    vertical-align: middle;
    border-radius: 4px;
    box-shadow: 0px 20px 30px -15px rgba(0, 0, 0, 0.226);
    cursor: pointer;
  }

  .download::before, .download::after {
    box-sizing: inherit;
    border-radius: inherit;
    content: "";
    position: absolute;
    width: 30px;
    height: 100%;
  }

  .download {
    transition: color 0.25s;
  }

  .download::before, .download::after {
    border: 2px solid transparent;
    width: 0;
    height: 0;
  }

  .download::before {
    top: 0;
    left: 0;
  }

  .download::after {
    bottom: 0;
    right: 0;
  }

  .download:focus {
    color: #039be5;
  }

  .download:focus::before, .download:focus::after {
    width: 100%;
    height: 100%;
  }

  .download .tooltip {
    visibility: hidden;
    width: 120px;
    background-color: #039be5;
    color: #fff;
    text-align: center;
    border-radius: 6px;
    padding: 5px 0;
    position: absolute;
    z-index: 1;
    bottom: 120%;
    left: 50%;
    margin-left: -60px;
  }

  .download .tooltip::after {
    content: "";
    position: absolute;
    top: 100%;
    left: 50%;
    margin-left: -5px;
    border-width: 5px;
    border-style: solid;
    border-color: #039be5 transparent transparent transparent;
  }

  .download:hover:not(:focus) .tooltip {
    visibility: visible;
  }
`;

export default Auction;
