import Slider from "react-slick";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
// import dogSupplies from "../../static/images/dogSupplies.jpg"
// import dogSupplies2 from "../../static/images/dogSupplies2.jpg"
import dogSupplies3 from "../../static/images/shoppingmallbanner.jpg";
import dogSupplies4 from "../../static/images/shoppingmallbanner2.jpg";
import dogSupplies5 from "../../static/images/shoppingmallbanner3.jpg";

function ShopCarousel() {
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
    <div
      className="slider-container"
      style={{ display: "block", width: "100%", marginBottom: "30px" }}
    >
      <Slider {...settings}>
        {/* <div>
          <img src={dogSupplies} alt="" style={{height: '400px', width: '100%', margin: "0 auto"}}/>
        </div>
        <div>
          <img src={dogSupplies2} alt="" style={{height: '400px', width: '100%', margin: "0 auto"}}/>
        </div> */}
        <div>
          <img
            src={dogSupplies5}
            alt=""
            style={{ height: "275px", width: "100%", margin: "0 auto" }}
          />
        </div>
        <div>
          <img
            src={dogSupplies3}
            alt=""
            style={{ height: "275px", width: "100%", margin: "0 auto" }}
          />
        </div>
        <div>
          <img
            src={dogSupplies4}
            alt=""
            style={{ height: "275px", width: "100%", margin: "0 auto" }}
          />
        </div>
      </Slider>
    </div>
  );
}
export default ShopCarousel;
