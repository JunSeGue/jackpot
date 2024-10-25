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
import "../../assets/scss/style.scss"
import React,{useState} from "react";
import apiClient from "../../../token/AxiosConfig";


const BoardAddFrom = () => {

    const [board, setBoard] = useState({
        title: '',
        content: '',
        type: 1,
        reg_date: new Date().toISOString()
    });

    const handleInputChange = (e) => {
        const {name, value} = e.target;
        setBoard({
            ...board,
            [name]: value
        });
    };

    const addBoard = () => {
        const formData = new FormData();
        formData.append('title', board.title);
        formData.append('content', board.content);
        formData.append('type', board.type);
        formData.append('regDate', board.reg_date);

        apiClient.post('admin/board/register', formData)
            .then(response => {
                alert("공지사항이 등록 되었습니다.");
                window.location.href = '/admin/boardtable';
            })
            .catch(error => {
                console.error('공지사항 등록 실패:', error);
            });
    };

    return (
        <Row>
            <Col>
                <Card>
                    <CardTitle tag="h6" className="border-bottom p-3 mb-0">
                        공지사항 등록
                    </CardTitle>
                    <CardBody>
                        <Form>
                            <FormGroup>
                                <Label for="title">제목</Label>
                                <Input
                                    id="title"
                                    name="title"
                                    placeholder="공지사항 제목"
                                    onChange={handleInputChange}
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="content">내용</Label>
                                <Input
                                    id="content"
                                    name="content"
                                    placeholder="공지사항 내용"
                                    onChange={handleInputChange}
                                />
                            </FormGroup>
                            <Button onClick={addBoard}>등록</Button>
                        </Form>
                    </CardBody>
                </Card>
            </Col>
        </Row>
    );
};

export default BoardAddFrom;
