import React, { useState, useEffect } from "react";
import Slider from "react-slick";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";

import styled from "styled-components";
import { apiNoToken } from "../../token/AxiosConfig";
import Dog from "../../dogList/Dog";

function DogCarousel() {
  const [dogs, setDogs] = useState([]);

  useEffect(() => {
    const dogListAPI = async () => {
      try {
        const response = await apiNoToken.get("dog/dogList", {
          params: {
            page: 1,
            size: 10,
            sort: "heart",
          },
        });
        setDogs(response.data.dogList);
      } catch (err) {
        console.error(err);
      }
    };
    dogListAPI();
  }, []);

  const settings = {
    infinite: true,
    slidesToShow: 4,
    slidesToScroll: 1,
    autoplay: true,
    speed: 3000,
    autoplaySpeed: 3000,
    cssEase: "linear",
  };

  return (
    <div
      className="slider-container"
      style={{ marginBottom: "200px", width: "100%" }}
    >
      <Slider {...settings}>
        {dogs?.length > 0 &&
          dogs.map((dog) => (
            <StyledWrapper key={dog.dogId}>
              <Dog dog={dog} className="card"></Dog>
            </StyledWrapper>
          ))}
      </Slider>
    </div>
  );
}

const StyledWrapper = styled.div`
  .card {
    transition: 0.4s;
  }

  .card:hover {
    translate: 0 -10px;
  }
`;

export default DogCarousel;
