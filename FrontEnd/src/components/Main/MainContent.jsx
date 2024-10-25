import Container from "@mui/material/Container";
import React from "react";
import {Box, Typography, Grid2} from "@mui/material";
import "../../static/css/font.css";
import {styled} from "@mui/material/styles";
import {useState, useEffect} from "react";
import apiClient from "../../token/AxiosConfig";
import {useNavigate} from "react-router-dom";
import DogCarousel from "./DogCarousel";
import AuctionCarousel from "../Auction/AuctionCarousel";

function MainContent() {
    const navigate = useNavigate();
    const [shops, setShops] = useState([]);

    useEffect(() => {
        apiClient
            .get(`shop/findList`, {
                params: {
                    size: 9,
                    page: 1,
                },
            })
            .then((res) => {
                console.log(res.data);
                setShops(res.data.dtoList);
            })
            .catch((err) => {
                console.log("error : ", err);
            });
    }, []);

    return (
        <>
            <Container
                maxWidth="false"
                style={{
                    width: "98%",
                    borderRadius: "10px",
                    backgroundColor: "rgba(255, 255, 255, 0.98)",
                    marginTop: "-80px",
                    boxShadow:
                        "rgba(0, 0, 0, 0.1) 0rem 0.25rem 0.5rem -0.0625rem, rgba(0, 0, 0, 0.06) 0rem 0.125rem 0.25rem -0.0625rem",
                    position: "relative ",
                    zIndex: 500,
                }}
            >
                <Box sx={{padding: "3.5rem"}}>
                    <Grid2 container spacing={20} justifyContent="center">
                        {/* 각 항목 */}
                        <Grid2 xs={12} md={4}>
                            <Box sx={{textAlign: "center", fontFamily: "BMJUA"}}>
                                <Typography
                                    variant="h4"
                                    component="h1"
                                    style={{color: "#f57e24"}}
                                    gutterBottom
                                >
                                    <span>100K+</span>
                                </Typography>
                                <Typography variant="h6" gutterBottom>
                                    현재 국내 유기견 수
                                </Typography>
                            </Box>
                        </Grid2>

                        <Grid2 xs={12} md={4}>
                            <Box sx={{textAlign: "center", fontFamily: "BMJUA"}}>
                                <Typography
                                    variant="h4"
                                    component="h1"
                                    style={{color: "#f57e24"}}
                                    gutterBottom
                                >
                                    약<span>12만</span>마리
                                </Typography>
                                <Typography variant="h6" gutterBottom>
                                    국내 유기견 안락사 수
                                </Typography>
                            </Box>
                        </Grid2>

                        <Grid2 xs={12} md={4}>
                            <Box sx={{textAlign: "center", fontFamily: "BMJUA"}}>
                                <Typography
                                    variant="h4"
                                    component="h1"
                                    style={{color: "#f57e24"}}
                                    gutterBottom
                                >
                                    <span>2000</span>만원
                                </Typography>
                                <Typography variant="h6" gutterBottom>
                                    현재 모인 금액
                                </Typography>
                            </Box>
                        </Grid2>
                    </Grid2>
                </Box>

                <Container maxWidth="lg" style={{paddingBottom: "100px"}}>
                    <Grid2
                        container
                        spacing={2}
                        justifyContent="center"
                        alignItems="center"
                        sx={{padding: "150px 0 150px 0"}}
                    >
                        <Grid2 xs={12} lg={6}>
                            <Typography variant="h2" style={{textAlign: "center"}}>
                                PPyPPy의 서비스를 소개합니다!
                            </Typography>
                            <Typography
                                variant="body1"
                                style={{
                                    fontSize: "20px",
                                    textAlign: "center",
                                    marginTop: "1rem",
                                }}
                            >
                                저희는 유기견 펀딩을 통해 안락사 위기의 개들을 보살피고
                                있습니다.
                                <br/>
                                펀딩 금액에 따른 회원 등급 분류로 쇼핑몰의 제품들을 더 저렴하게
                                구매하실 수 있도록 경매를 진행합니다.
                            </Typography>
                        </Grid2>
                    </Grid2>
                </Container>

                <DogCarousel/>

                {/*애완 용품*/}
                <Grid2 container spacing={1} sx={{marginBottom: "150px"}}>
                    <FixedLeftSidebar size={{xs: 6, md: 3}}>
                        <StyledBox>
                            <Typography variant="h4">Pet Supplies Shop</Typography>
                            <Typography variant="body2">
                                반려견 사료 및 생활용품
                            </Typography>
                        </StyledBox>
                    </FixedLeftSidebar>
                    <CardContainer container size={{xs: 6, md: 9}}>
                        {shops?.length > 0 &&
                            shops.map((shop, index) => (
                                <Grid2 key={index} size={{xs: 2, sm: 4, md: 4}}>
                                    <StyledCard
                                        component="a"
                                        onClick={() => navigate(`/shop/${shop.shopId}`)}
                                    >
                                        <StyledBox>
                                            <StyledImg
                                                src={shop.mainImage}
                                                alt={shop.name}
                                            />
                                            <Typography variant="h6">{shop.name}</Typography>
                                            <Typography variant="button">{shop.price}원</Typography>
                                        </StyledBox>
                                    </StyledCard>
                                </Grid2>
                            ))}
                    </CardContainer>
                </Grid2>
            </Container>
        </>
    );
}

const FixedLeftSidebar = styled(Grid2)(({theme}) => ({
    position: "sticky",
    top: theme.spacing(12), // Adjust this value as needed
    zIndex: 1000,
}));

const CardContainer = styled(Grid2)`
  margin-top: 100px;
  margin-bottom: 200px;
  display: flex;
  flex-flox: row wrap;
`;

const StyledBox = styled(Box)`
  display: flex;
  flex-direction: column;
  position: sticky;
  top: 100px;
  padding: 8px;
`;

const StyledImg = styled("img")`
  width: 100%;
  height: 50%;
`;

const StyledCard = styled(Box)`
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  text-decoration: none;
  height: 100%;
  margin-bottom: 20px;
`;

export default MainContent;
