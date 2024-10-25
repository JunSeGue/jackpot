import {Card, CardBody, CardTitle, Table} from "reactstrap";
import React from "react";
import {useState, useEffect, useCallback} from "react";
import Button from "../button/BoardButton";
import apiClient from "../../../token/AxiosConfig";
import {useNavigate, useLocation} from 'react-router-dom';
import Search from "../Search";
import PageComponent from "../../../dogList/PageComponent";

const BoardTables = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const [boards, setBoards] = useState([]);
    const [searchText, setSearchText] = useState("");
    const [pageInfo, setPageInfo] = useState({
        page: 1,
        size: 10,
    });
    const [totalPages, setTotalPages] = useState(1);
    // const [sortOrder, setSortOrder] = useState("latest");


    const fetchBoards = useCallback((page, search = "") => {
        const endpoint = search ? `/admin/board/search/${search}` : `/admin/board/findAll`;
        apiClient
            .get(endpoint, {
                params: {page: page, size: pageInfo.size, search: search}
            })
            .then((res) => {
                if (Array.isArray(res.data.dtoList)) {
                    setBoards(res.data.dtoList);
                    console.log(boards);
                } else {
                    setBoards([]);
                }
                setTotalPages(Math.ceil(res.data.total / pageInfo.size));
            })
            .catch((err) => {
                console.error(err);
            });
    }, [pageInfo.size]);

    useEffect(() => {
        fetchBoards(pageInfo.page, searchText);
    }, [pageInfo.page, searchText, fetchBoards]);

    useEffect(() => {
        const queryParams = new URLSearchParams(location.search);
        // const sortOrderFromUrl = queryParams.get("sortOrder");
        const pageFromUrl = queryParams.get("page");

        // if (sortOrderFromUrl) {
        //     setSortOrder(sortOrderFromUrl);
        // }

        if (pageFromUrl) {
            setPageInfo(prev => ({...prev, page: parseInt(pageFromUrl)}));
        }
    }, [location]);

    const handleSearch = useCallback((newSearchText) => {
        setSearchText(newSearchText);
        setPageInfo(prev => ({...prev, page: 1}));
    }, []);

    const updateUrlParams = useCallback((page) => {
        const queryParams = new URLSearchParams();
        // if (sortOrder) queryParams.set("sortOrder", sortOrder);
        if (page) queryParams.set("page", page.toString());
        navigate({
            search: queryParams.toString(),
        });
    }, [navigate]);

    const handlePageChange = useCallback((newPage) => {
        setPageInfo(prev => ({...prev, page: newPage}));
        updateUrlParams( newPage);
    }, [ updateUrlParams]);


    const sortedBoards = boards.sort((a, b) => {
        // 공지사항(1), 1대1 문의게시판(3), 자유게시판(2) 순으로 정렬
        const order = [1, 3, 2];
        return order.indexOf(a.type) - order.indexOf(b.type);
    });
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
                        <CardTitle tag="h5">게시글 목록</CardTitle>
                        <Search onSearch={handleSearch}/>
                        <Button/>
                    </div>
                    <Table className="no-wrap mt-3 align-middle" responsive borderless>
                        <thead>
                        <tr>
                            <th>제목</th>
                            <th>내용</th>
                            <th>게시글 종류</th>
                            <th>등록 날짜</th>
                        </tr>
                        </thead>
                        <tbody>
                        {sortedBoards.map((board, index) => (
                            <tr key={index} className="border-top">
                                <td>
                                    <div className="d-flex align-items-center p-2">
                                        <div className="ms-3">
                                            <h6 className="mb-0">{board.title}</h6>
                                        </div>
                                    </div>
                                </td>
                                <td>{board.content}</td>
                                <td>
                                    {board.type === 1 && '공지사항'}
                                    {board.type === 2 && '자유게시판'}
                                    {board.type === 3 && '1대1 문의게시판'}
                                </td>
                                <td>{board.regdate}</td>
                                <td>
                                <button onClick={() => navigate(`/admin/boarddetailform/${board.boardId}`)}
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
                    onNext={() => handlePageChange(Math.min(pageInfo.page + 1, totalPages))}
                />
            </Card>
        </div>
    );
};

export default BoardTables;
