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
import React, {useState} from "react";
import apiClient from "../../../token/AxiosConfig";

const DogAddFrom = () => {

    const [dog, setDog] = useState({
        name: '',
        species: '',
        age: 0,
        gender: 0,
        heart: 0,
        videoUrl: '',
        dogDetail: '',
        title: ''
    });

    const [files, setFiles] = useState({
        mainImage : File,
        detailImage1 : File,
        detailImage2 : File,
        detailImage3 : File,
        detailImage4 : File
    });

    const handleInputChange = (e) => {
        const {name, value} = e.target;
        setDog({
            ...dog,
            [name]: value,
        });
    };

    const handleFileChange = (e) =>{
        const {name, files: fileList} = e.target;
        setFiles({
            ...files,
            [name]: fileList[0],
        });
    }

    const addDog = () => {
        const formData = new FormData();
        formData.append('dogData', new Blob([JSON.stringify(dog)]));
        for (const key in files){
            if (files[key]){
                formData.append('files', files[key]);
            }
        }

        apiClient.post('/admin/dog/register', formData)
            .then(response => {
                alert("유기견이 등록되었습니다.");
                window.location.href = '/admin/dogtable';
            })
            .catch(error => {
                console.error('유기견 등록 실패:', error);
            });
    };

    return (
        <Row>
            <Col>
                {/* --------------------------------------------------------------------------------*/}
                {/* Card-1*/}
                {/* --------------------------------------------------------------------------------*/}
                <Card>
                    <CardTitle tag="h6" className="border-bottom p-3 mb-0">
                        강아지 등록
                    </CardTitle>
                    <CardBody>
                        <Form>
                            <FormGroup>
                                <Label for="title">제목</Label>
                                <Input
                                    id="title"
                                    name="title"
                                    placeholder="제목"
                                    onChange={handleInputChange}
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="name">이름</Label>
                                <Input
                                    id="name"
                                    name="name"
                                    placeholder="강아지 이름"
                                    onChange={handleInputChange}
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="species">종</Label>
                                <Input
                                    id="species"
                                    name="species"
                                    placeholder="강아지 종"
                                    onChange={handleInputChange}
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="age">나이</Label>
                                <Input id="age" name="age" placeholder="강아지 나이"
                                    onChange={handleInputChange}>
                                </Input>
                            </FormGroup>
                            <FormGroup>
                                <Label for="gender">성별</Label>
                                <Input
                                    id="gender"
                                    name="gender"
                                    type="select"
                                    onChange={handleInputChange}
                                >
                                    <option value={0}>수컷</option>
                                    <option value={1}>암컷</option>
                                </Input>
                            </FormGroup>
                            <FormGroup>
                                <Label for="videoUrl">영상URL</Label>
                                <Input
                                    id="videoUrl"
                                    name="videoUrl"
                                    placeholder="https://www.videoUrl.com"
                                    onChange={handleInputChange}
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="dogDetail">설명</Label>
                                <Input id="dogDetail" name="dogDetail" type="textarea"
                                    onChange={handleInputChange}/>
                            </FormGroup>
                            <FormGroup>
                                <Label for="mainImage">메인 사진</Label>
                                <Input id="mainImage" name="mainImage" type="file"
                                    onChange={handleFileChange}/>
                            </FormGroup>
                            <FormGroup>
                                <Label for="detailImage1">세부 사진1</Label>
                                <Input id="detailImage1" name="detailImage1" type="file"
                                    onChange={handleFileChange}/>
                            </FormGroup>
                            <FormGroup>
                                <Label for="detailImage2">세부 사진2</Label>
                                <Input id="detailImage2" name="detailImage2" type="file"
                                    onChange={handleFileChange}/>
                            </FormGroup>
                            <FormGroup>
                                <Label for="detailImage3">세부 사진3</Label>
                                <Input id="detailImage3" name="detailImage3" type="file"
                                    onChange={handleFileChange}/>
                            </FormGroup>
                            <FormGroup>
                                <Label for="detailImage4">세부 사진4</Label>
                                <Input id="detailImage4" name="detailImage4" type="file"
                                    onChange={handleFileChange}/>
                            </FormGroup>
                            <Button onClick={addDog}>등록</Button>
                        </Form>
                    </CardBody>
                </Card>
            </Col>
        </Row>
    );
};

export default DogAddFrom;
