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
import React, {useEffect, useState} from "react";
import {useParams} from 'react-router-dom';
import apiClient from "../../../token/AxiosConfig";

const ShopDetailForm = () => {
    const {shopId} = useParams();  // URL에서 shopId를 가져옴
    const [shop, setShop] = useState({
        name: '',
        price: '',
        category: '',
        detail: '',
        img: null
    });

    const formData = new FormData(); // 파일이 포함된 폼 데이터 생성
    formData.append("shopId", shopId);
    formData.append("name", shop.name);
    formData.append("price", shop.price);
    formData.append("category", shop.category);
    formData.append("detail", shop.detail);
    formData.append("buy_count", shop.buy_count);
    formData.append("cell_count", shop.cell_count);

    console.log(shop.buy_count);

    if (shop.img) {
        formData.append("img", shop.img); // 파일이 존재할 때만 추가
    }

    const handleInputChange = (e) => {
        const {name, value} = e.target;
        setShop({
            ...shop,
            [name]: value
        });
    };

    const handleFileChange = (e) => {
        setShop({
            ...shop,
            img: e.target.files[0]
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

    const editShop = () => {
        window.confirm("정말 수정 하시겠습니까?");
        apiClient.put(`/admin/shop/edit/${shopId}`, formData, {
            headers: {
                "Content-Type": 'application/json'
            }
        })
            .then(() => {
                alert("상품이 수정 되었습니다.");
                window.location.reload();
                console.error('상품 수정 성공');
            })
            .catch(error => {
                console.error('상품 수정 실패:', error);
            });
    };

    const removeShop = () => {
        window.confirm("정말 삭제 하시겠습니까?");
        apiClient.delete(`/admin/shop/remove/${shopId}`)
            .then(() => {
                alert("상품이 삭제 되었습니다.");
                window.location.href = "/admin/shoptable";
                console.error('상품 삭제 성공');
            })
            .catch(error => {
                console.error('상품 삭제 실패:', error);
            });
    };

    return (
        <Row>
            <Col>
                <Card>
                    <CardTitle tag="h6" className="border-bottom p-3 mb-0">
                        상품 상세
                    </CardTitle>
                    <CardBody>
                        <Form>
                            <FormGroup>
                                <Label for="name">상품명</Label>
                                <Input
                                    id="name"
                                    name="name"
                                    value={shop.name}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="price">상품 가격</Label>
                                <Input
                                    id="price"
                                    name="price"
                                    value={shop.price}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="category">종류</Label>
                                <Input
                                    id="category"
                                    name="category"
                                    type="select"
                                    value={shop.category}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                >
                                    <option value={0}>식품</option>
                                    <option value={1}>장난감</option>
                                    <option value={2}>가구</option>
                                    <option value={3}>개모차</option>
                                </Input>
                            </FormGroup>
                            <FormGroup>
                                <Label for="detail">설명</Label>
                                <Input id="detail"
                                       name="detail"
                                       type="textarea"
                                       value={shop.detail}
                                       onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="img">사진</Label>
                                <Input
                                    id="img"
                                    name="img"
                                    type="file"
                                    onChange={handleFileChange} // 파일 변경 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Button onClick={editShop} style={{marginRight: '20px'}}>수정</Button>
                                <Button onClick={removeShop} style={{marginRight: '20px'}}>삭제</Button>
                            </FormGroup>
                        </Form>
                    </CardBody>
                </Card>
            </Col>
        </Row>
    );
};

export default ShopDetailForm;
