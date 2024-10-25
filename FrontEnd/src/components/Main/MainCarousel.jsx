import Slider from "react-slick";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import mainCarousel1 from "../../static/mainCarousel1.jpg";
import mainCarousel2 from "../../static/mainCarousel2.jpg";
import mainCarousel3 from "../../static/mainCarousel3.jpg";
import mainCarousel4 from "../../static/mainCarousel4.jpg";

function MainCarousel() {
  const mainCarousels = [
    mainCarousel1,
    mainCarousel2,
    mainCarousel3,
    mainCarousel4,
  ];

  const settings = {
    dots: false,
    infinite: true,
    speed: 500,
    slidesToShow: 1,
    slidesToScroll: 1,
    autoplay: true,
    autoplaySpeed: 4000,
    arrows: false,
  };
  return (
    <div className="slider-container" style={{ display: "block" }}>
      <Slider {...settings}>
        {mainCarousels.map((carousel, index) => (
          <div key={index}>
            <img
              src={carousel}
              alt={`carousel-${index}`}
              style={{ height: "700px", width: "100%" }}
            />
          </div>
        ))}
      </Slider>
    </div>
  );
}

export default MainCarousel;
