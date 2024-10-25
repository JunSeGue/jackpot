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

const MemberDetailForm = () => {
    const {email} = useParams();  // URL에서 email 가져옴
    console.log(email)
    const [member, setMember] = useState({
        // memberID: 0,
        name: '',
        age: '',
        nickName: '',
        email: '',
        address: '',
        pwd: '',
        phone: '',
        isAdmin: 0,
    });


    const formData = new FormData(); // 파일이 포함된 폼 데이터 생성
    // formData.append("memberId", member.memberID);
    formData.append("name", member.name);
    formData.append("nickName", member.nickName);
    formData.append("email", member.email);
    formData.append("address", member.address);
    formData.append("phone", member.phone);
    formData.append("pwd", member.pwd);
    formData.append("isAdmin", member.isAdmin);

    const handleInputChange = (e) => {
        const {name, value} = e.target;
        setMember({
            ...member,
            [name]: name === 'isAdmin' ? parseInt(value) : value
        });
    };

    useEffect(() => {
        apiClient
            .get(`/admin/member/findOne/${email}`) 
            .then((res) => {
                console.log(res.data)
                setMember(res.data);
            })
            .catch((err) => {
                console.error(err);
            });
    }, [email]);

    // const editMember = () => {
    //     window.confirm("정말 수정 하시겠습니까?");
    //     apiClient.put(`/admin/member/edit/${member.memberId}`, formData, {
    //         headers: {
    //             "Content-Type": 'application/json'
    //         }
    //     })
    //         .then(() => {
    //             alert("회원 정보가 수정 되었습니다.");
    //             window.location.reload();
    //             console.error('정보 수정 성공');
    //         })
    //         .catch(error => {
    //             console.error('정보 수정 실패:', error);
    //         });
    // };

    console.log(member)
    const removeMember = () => {
        window.confirm("정말 탈퇴 처리 하시겠습니까?");
        apiClient.delete(`/admin/member/remove/${member.memberID}`)
            .then(() => {
                alert("탈퇴 처리 되었습니다.");
                window.location.href = "/admin/membertable";
                console.error('탈퇴 성공');
            })
            .catch(error => {
                console.error('탈퇴 실패:', error);
            });
    };

    return (
        <Row>
            <Col>
                <Card>
                    <CardTitle tag="h6" className="border-bottom p-3 mb-0">
                        회원 정보
                    </CardTitle>
                    <CardBody>
                        <Form>
                            <FormGroup>
                                <Label for="name">이름</Label>
                                <Input
                                    id="name"
                                    name="name"
                                    value={member.name}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="email">이메일</Label>
                                <Input
                                    id="email"
                                    name="email"
                                    value={member.email}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="nickName">닉네임</Label>
                                <Input
                                    id="nickName"
                                    name="nickName"
                                    value={member.nickName}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="address">주소</Label>
                                <Input
                                    id="address"
                                    name="address"
                                    value={member.address}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="phone">전화번호</Label>
                                <Input
                                    id="phone"
                                    name="phone"
                                    value={member.phone}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                />
                            </FormGroup>
                            <FormGroup>
                                <Label for="isAdmin">회원 형태</Label>
                                <Input
                                    id="isAdmin"
                                    name="isAdmin"
                                    type="select"
                                    value={member.isAdmin}
                                    onChange={handleInputChange} // 이벤트 핸들러 추가
                                >
                                    <option value={0}>회원</option>
                                    <option value={1}>관리자</option>
                                </Input>
                            </FormGroup>
                            {/*<Button onClick={editMember} style={{marginRight: '10px'}}>수정</Button>*/}
                            <Button onClick={removeMember}>삭제</Button>
                        </Form>
                    </CardBody>
                </Card>
            </Col>
        </Row>
    );
};

export default MemberDetailForm;
