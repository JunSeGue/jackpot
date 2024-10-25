import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardBody, CardTitle, Table } from "reactstrap";
import apiClient from "../../../token/AxiosConfig";
import Search from "../Search";
import PageComponent from "../../../dogList/PageComponent";

const MemberTables = () => {
  const navigate = useNavigate();
  const [members, setMembers] = useState([]);
  const [pageInfo, setPageInfo] = useState({
    page: 1, // 페이지는 1부터 시작
    size: 9,
  });
  const [totalPages, setTotalPages] = useState(1);

  const handlePageChange = (page) => {
    setPageInfo((prevInfo) => ({
      ...prevInfo,
      page: page,
    }));
  };

  const memberListAPI = async () => {
    try {
      const response = await apiClient.get("/admin/member/findAll", {
        params: {
          page: pageInfo.page - 1, // 서버로 보낼 때는 0부터 시작하는 인덱스로 변환
          size: pageInfo.size,
        },
      });
      setMembers(response.data.content);
      setTotalPages(response.data.totalPages);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    memberListAPI();
  }, [pageInfo]);

  const handlePrev = () => {
    if (pageInfo.page > 1) {
      handlePageChange(pageInfo.page - 1);
    }
  };

  const handleNext = () => {
    if (pageInfo.page < totalPages) {
      handlePageChange(pageInfo.page + 1);
    }
  };

  return (
    <div>
      <Card>
        <CardBody>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <CardTitle tag="h5">회원 목록</CardTitle>
            <Search />
          </div>
          <Table className="no-wrap mt-3 align-middle" responsive borderless>
            <thead>
              <tr>
                <th>이름</th>
                <th>닉네임</th>
                <th>주소</th>
                <th>전화번호</th>
                <th>등급</th>
              </tr>
            </thead>
            <tbody>
              {members.map((member, index) => (
                <tr key={index} className="border-top">
                  <td>
                    <div className="d-flex align-items-center p-2">
                      <div className="ms-3">
                        <h6 className="mb-0">{member.name}</h6>
                        <span className="text-muted">{member.email}</span>
                      </div>
                    </div>
                  </td>
                  <td>{member.nickName}</td>
                  <td>{member.address}</td>
                  <td>{member.phone}</td>
                  <td>{member.grade === 1 ? "관리자" : "회원"}</td>
                  <td>
                    <button
                      onClick={() =>
                        navigate(`/admin/memberdetailform/${member.email}`)
                      }
                      style={{ border: "none", background: "white" }}
                    >
                      상세보기
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </CardBody>
        <PageComponent
          pageInfo={pageInfo}
          totalPages={totalPages}
          onPageChange={handlePageChange}
          onPrev={handlePrev}
          onNext={handleNext}
        />
      </Card>
    </div>
  );
};

export default MemberTables;
