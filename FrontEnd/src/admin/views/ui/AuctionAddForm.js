import {
    Card,
    Row,
    Col,
    CardTitle,
    CardBody,
    Button,
    Form,
    FormGroup,
    Label,
    Input,
} from "reactstrap";
import "../../assets/scss/style.scss";
import React, {useState, useEffect} from "react";
import apiClient from "../../../token/AxiosConfig";
import { useParams } from "react-router-dom";

const AuctionAddFrom = () => {
    const {shopId} = useParams();
    const [shop, setShop] = useState([]);
    const [auction, setAuction] = useState({
        start_price: 0,
        start_time: new Date().toISOString().slice(0, 19),
    });

    console.log(shopId);

    const handleInputChange = (e) => {
        const {name, value} = e.target;
        setAuction({
            ...auction,
            [name]: name === "start_price" ? parseFloat(value) : value  // 숫자 변환
        });
    };

    useEffect(() => {
        apiClient
            .get(`/admin/shop/findOne/${shopId}`)  // 가져온 shopId로 상품 정보 요청
            .then((res) => {
                setShop(res.data);
            })
            .catch((err) => {
                console.error(err);
            });
    }, [shopId]);

    const addAuction = () => {
        const formData = new FormData();
        formData.append('startPrice', auction.start_price);
        formData.append('startTime', auction.start_time);
        
        apiClient
          .post(`auction/register/${shopId}`, formData, {
            headers: {
              "Content-Type": "application/json",
            },
          })
          .then((response) => {
            alert("경매 상품이 등록 되었습니다.");
            window.location.href='admin/auctiontable';
          })
          .catch((error) => {
            console.error("경매 상품 등록 실패:", error);
          });
    };

    return (
      <Row>
        <Col>
          <Card>
            <CardTitle tag="h6" className="border-bottom p-3 mb-0">
              경매 상품 등록
            </CardTitle>
            <CardBody>
              <Form>
                <FormGroup>
                  <Label for="name">상품명</Label>
                  <Input
                    id="name"
                    name="name"
                    placeholder="상품명"
                    value={shop.name || ""}
                    readOnly
                  />
                </FormGroup>
                <FormGroup>
                  <Label for="price">가격</Label>
                  <Input
                    id="price"
                    name="price"
                    placeholder="상품가격"
                    value={shop.price || ""}
                    readOnly
                  />
                </FormGroup>
                <FormGroup>
                  <Label for="category">종류</Label>
                  <Input
                    id="category"
                    name="category"
                    type="select"
                    value={shop.category || ""}
                    readOnly
                  >
                    <option value={0}>식품</option>
                    <option value={1}>장난감</option>
                    <option value={2}>가구</option>
                    <option value={3}>개모차</option>
                  </Input>
                </FormGroup>
                <FormGroup>
                  <Label for="detail">설명</Label>
                  <Input
                    id="detail"
                    name="detail"
                    placeholder="상품설명"
                    type="textarea"
                    value={shop.detail || ""}
                    readOnly
                  />
                </FormGroup>
                <FormGroup>
                  <Label for="buy_count">재고</Label>
                  <Input
                    id="buy_count"
                    name="buy_count"
                    placeholder="재고"
                    type="number"
                    value={(shop.buy_count - shop.cell_count) || ""}
                    readOnly
                  />
                </FormGroup>
                <FormGroup>
                  <Label for="start_time">경매 시작 날짜</Label>
                  <Input
                    id="start_time"
                    name="start_time"
                    type="datetime-local"
                    value={auction.start_time || ""}
                    onChange={handleInputChange}
                  />
                </FormGroup>
                <FormGroup>
                  <Label for="start_price">경매 시작 가격</Label>
                  <Input
                    id="start_price"
                    name="start_price"
                    type="number"
                    value={auction.start_price || ""}
                    onChange={handleInputChange}
                  />
                </FormGroup>
                <Button onClick={addAuction}>등록</Button>
              </Form>
            </CardBody>
          </Card>
        </Col>
      </Row>
    );
};

export default AuctionAddFrom;
