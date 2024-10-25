import Slider from "react-slick";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import styled from "styled-components";
import React, {useEffect, useState} from "react";
import apiClient from "../../token/AxiosConfig";

function AuctionCarousel({shopId}) {
  const [product, setProductDetails] = useState({

    detail: "",
    detailImages: [],
  });
  useEffect(() => {
    const fetchProductDetails = async () => {
      console.log(shopId);
      try {
        const response = await apiClient.get(`/shop/findOne/${shopId}`);
        const data = response.data;

        setProductDetails({
          detail: data.detail || "",
          detailImages: [
            data.detailImage1,
            data.detailImage2,
            data.detailImage3,
            data.detailImage4,
          ],
        });
      } catch (error) {
        console.error("상품 세부 정보를 불러오는 중 오류 발생:", error);
      }
    };
    fetchProductDetails();
  }, [shopId]);

  const settings = {
    dots: false,
    infinite: true,
    speed: 500,
    slidesToShow: 1,
    slidesToScroll: 1,
    autoplay: true,
    autoplaySpeed: 4000,
    arrows: true,
  };
  return (
    <SliderContainer>
      <Slider {...settings}>
        {product.detailImages.map((image, index) => (
          <div key={index} style={{borderRadius:'20px', border:'none'}}>
            <img
              src={image}
              alt={`carousel-${index}`}
              style={{ height: "400px", width: "100%", borderRadius:'20px', border:'none' }}
            />
          </div>
        ))}
      </Slider>
    </SliderContainer>
  );
}

const SliderContainer = styled.div`
  position: relative;
  .slick-prev,
  .slick-next {
    z-index: 1;
    top: 50%;
    transform: translateY(-50%);
    width: 40px;
    height: 40px;
    background-color: none;
    border-radius: 50%;
    display: flex;
    justify-content: center;
    align-items: center;
  }

  .slick-prev {
    left: 10px;
  }

  .slick-next {
    right: 10px;
  }

  .slick-prev:before,
  .slick-next:before {
    font-size: 20px;
    color: white;
  }
`;

export default AuctionCarousel;
