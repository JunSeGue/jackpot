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
import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import apiClient from "../../../token/AxiosConfig";

const MemberDetailForm = () => {
  const { boardId } = useParams();

  const [board, setBoard] = useState({
    // memberID: 0,
    title: "",
    content: "",
    type: 1,
  });

  const formData = new FormData(); // 파일이 포함된 폼 데이터 생성
  // formData.append("memberId", member.memberID);
  formData.append("title", board.title);
  formData.append("content", board.content);
  formData.append("type", board.type);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setBoard({
      ...board,
      [name]: name === value,
    });
  };

  useEffect(() => {
    apiClient
      .get(`/admin/board/findOne/${boardId}`)
      .then((res) => {
        console.log(res.data);
        setBoard(res.data);
      })
      .catch((err) => {
        console.error(err);
      });
  }, [boardId]);

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

  // console.log(member)
  const removeBoard = () => {
    window.confirm("정말 삭제 하시겠습니까?");
    apiClient
      .delete(`/admin/board/remove/${boardId}`)
      .then(() => {
        alert("삭제 되었습니다.");
        window.location.href = "/admin/boardtable";
        console.error("삭제 성공");
      })
      .catch((error) => {
        console.error("삭제 실패:", error);
      });
  };

  return (
    <Row>
      <Col>
        <Card>
          <CardTitle tag="h6" className="border-bottom p-3 mb-0">
            게시판
          </CardTitle>
          <CardBody>
            <Form>
              <FormGroup>
                <Label for="title">제목</Label>
                <Input
                  id="title"
                  name="title"
                  value={board.title}
                  onChange={handleInputChange} // 이벤트 핸들러 추가
                />
              </FormGroup>
              <FormGroup>
                <Label for="content">내용</Label>
                <Input
                  id="content"
                  name="content"
                  value={board.content}
                  onChange={handleInputChange} // 이벤트 핸들러 추가
                />
              </FormGroup>
              <FormGroup>
                <Label for="type">게시판 종류</Label>
                <Input
                  id="type"
                  name="type"
                  type="select"
                  value={board.type}
                  onChange={handleInputChange} // 이벤트 핸들러 추가
                >
                  <option value={1}>공지사항</option>
                  <option value={2}>자유게시판</option>
                  <option value={3}>1대1문의게시판</option>
                </Input>
              </FormGroup>
              {/*<Button onClick={editMember} style={{marginRight: '10px'}}>수정</Button>*/}
              <Button onClick={removeBoard}>삭제</Button>
            </Form>
          </CardBody>
        </Card>
      </Col>
    </Row>
  );
};

export default MemberDetailForm;
