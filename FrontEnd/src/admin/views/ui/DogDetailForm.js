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
    const {dogId} = useParams();  // URL에서 shopId를 가져옴
    const [dog, setDog] = useState({
        name: '',
        age: 0,
        species: '',
        heart: 0,
        gender: 0,
        dogDetail: '',
        img: null
    });

    const formData = new FormData(); // 파일이 포함된 폼 데이터 생성
    formData.append("dogId", dog.dogId);
    formData.append("name", dog.name);
    formData.append("age", dog.age);
    formData.append("heart", dog.heart);
    // formData.append("species", dog.species);
    formData.append("dogDetail", dog.dogDetail);
    if (dog.img) {
        formData.append("img", dog.img); // 파일이 존재할 때만 추가
    }

    const handleInputChange = (e) => {
        const {name, value} = e.target;
        setDog({
            ...dog,
            [name]: value
        });
    };

    const handleFileChange = (e) => {
        setDog({
            ...dog,
            img: e.target.files[0]
        });
    };

    useEffect(() => {
        apiClient
            .get(`/admin/dog/findOne/${dogId}`)
            .then((res) => {
                console.log(res.data);
                setDog(res.data);
            })
            .catch((err) => {
                console.error(err);
            });
    }, [dogId]);

    const editDog = () => {
        window.confirm("정말 수정 하시겠습니까?");
        apiClient.post(`admin/shop/edit`, formData, {
            headers: {
                "Content-Type": 'application/json'
            }
        })
            .then(() => {
                alert("수정 되었습니다.");
                window.location.reload();
                console.error('정보 수정 성공');
            })
            .catch(error => {
                console.error('정보 수정 실패:', error);
            });
    };

    const removeDog = () => {
        window.confirm("정말 삭제 하시겠습니까?");
        apiClient.delete(`admin/dog/remove/${dogId}`)
            .then(() => {
                alert("삭제 되었습니다.");
                window.location.href = "/admin/dogtable";
                console.log('삭제 성공');
            })
            .catch(error => {
                console.error('삭제 실패:', error);
            });
    };

    return (
        <Row>
            <Col>
                <Card>
                    <CardTitle tag="h6" className="border-bottom p-3 mb-0">
                        강아지 정보
                    </CardTitle>
                    <CardBody>
                        <Form>
                            <FormGroup>
                                <Label for="name">이름</Label>
                                <Input
                                    id="name"
                                    name="name"
                                    value={dog.name}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="age">나이</Label>
                                <Input
                                    id="age"
                                    name="age"
                                    value={dog.age}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            {/*<FormGroup>*/}
                            {/*    <Label for="species">종</Label>*/}
                            {/*    <Input*/}
                            {/*        id="species"*/}
                            {/*        name="species"*/}
                            {/*        value={dog.species}*/}
                            {/*        onChange={handleInputChange} // 이벤트 핸들러 추가*/}
                            {/*    />*/}
                            {/*</FormGroup>*/}
                            <FormGroup>
                                <Label for="gender">성별</Label>
                                <Input
                                    id="gender"
                                    name="gender"
                                    type="select"
                                    value={dog.gender}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                >
                                    <option value={0}>수컷</option>
                                    <option value={1}>암컷</option>
                                </Input>
                            </FormGroup>
                            <FormGroup>
                                <Label for="dogDetail">설명</Label>
                                <Input id="dogDetail"
                                       name="dogDetail"
                                       type="textarea"
                                       value={dog.dogDetail}
                                       onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="heart">좋아요 수</Label>
                                <p>{dog.heart}</p>
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
                                <Button onClick={editDog} style={{marginRight: '20px'}}>수정</Button>
                                <Button onClick={removeDog}>삭제</Button>
                            </FormGroup>
                        </Form>
                    </CardBody>
                </Card>
            </Col>
        </Row>
    );
};

export default ShopDetailForm;
