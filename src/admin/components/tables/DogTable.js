import {Card, CardBody, CardTitle, Table} from "reactstrap";
import React from "react";
import {useState, useEffect} from "react";
import Button from "../button/DogButton";
import apiClient from "../../../token/AxiosConfig";
import DetailButton from "../button/DetailButton"
import {useNavigate} from 'react-router-dom';
import PageComponent from "../../../dogList/PageComponent";

const DogTables = () => {
    const navigate = useNavigate();
    const [dogsData, setDogsData] = useState([]);
    const [pageInfo, setPageInfo] = useState({
        sort: "heart",
        page: 1,
        size: 12,
    });
    const [totalPages, setTotalPages] = useState();
    const [loading, setLoading] = useState(true); // 로딩 상태 관리

    useEffect(() => {
        dogListAPI(pageInfo);
    }, [pageInfo]);


    const handlePageChange = (page) => {
        setPageInfo((prevInfo) => ({
            ...prevInfo,
            page,
        }));
    };

    const dogListAPI = async () => {
        try {
            const response = await apiClient.get("/admin/dog/dogList", {
                params: pageInfo,
            });
            console.log(response.data);
            setDogsData(response.data);

            setTotalPages(Math.ceil(response.data.totalDogNum / pageInfo.size));

            setLoading(false);
            setDogsData(response.data.dogList);
        } catch (err) {
            console.error(err);
        }
    };

    const handleHeartToggle = () => {
        // setPageInfo((prevInfo) => ({
        //   ...prevInfo,
        //   page: 1,
        // }));
        dogListAPI();
    };

    return (
        <div>
            <Card>
                <CardBody>
                    <div style={{display: "flex", justifyContent: "space-between", alignItems: "center"}}>
                        <CardTitle tag="h5">강아지 목록</CardTitle>
                        <Button/>
                    </div>

                    <Table className="no-wrap mt-3 align-middle" responsive borderless>
                        <thead>
                        <tr>
                            <th>이름</th>
                            <th>종</th>
                            <th>좋아요수</th>
                            <th>등록일자</th>
                        </tr>
                        </thead>
                        <tbody>
                        {dogsData.map((dogs, index) => (
                            <tr key={index} className="border-top">
                                <td>
                                    <div className="d-flex align-items-center p-2">
                                        <div className="ms-3">
                                            <h6 className="mb-0">{dogs.name}</h6>
                                        </div>
                                    </div>
                                </td>
                                <td>{dogs.species}</td>
                                <td>{dogs.heart}</td>
                                <td>{dogs.regDate}</td>
                                <td>
                                    <button onClick={() => navigate(`/admin/dogdetailform/${dogs.dogId}`)}
                                            style={{border: "none", background: "white"}}>상세보기
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
                    onPrev={() => handlePageChange(Math.max(pageInfo.page - 1, 1))}
                    onNext={() =>
                        handlePageChange(Math.min(pageInfo.page + 1, totalPages))
                    }
                />
            </Card>
        </div>
    );
};

export default DogTables;