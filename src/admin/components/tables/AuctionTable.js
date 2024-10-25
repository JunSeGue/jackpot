import React, {useState, useEffect, useCallback} from "react";
import {useLocation, useNavigate} from 'react-router-dom';
import {Card, CardBody, CardTitle, Table} from "reactstrap";
import Button from "../button/ShopButton";
import apiClient from "../../../token/AxiosConfig";
import Search from "../Search";
import PageComponent from "../../../dogList/PageComponent";

const AuctionsTables = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const [auctions, setAuctions] = useState([]);
    const [searchText, setSearchText] = useState("");
    const [pageInfo, setPageInfo] = useState({
        page: 1,
        size: 9,
    });
    const [totalPages, setTotalPages] = useState(1);
    const [sortOrder, setSortOrder] = useState("latest");

    const fetchAuctions = useCallback((page, search = "") => {
        const endpoint = search ? `/auction/search/${search}` : `/auction/findList`;
        apiClient
            .get( endpoint, {
                params: {page: page, size: pageInfo.size}
            })
            .then((res) => {
                if (Array.isArray(res.data.dtoList)) {
                    console.log(res.data)
                    setAuctions(res.data.dtoList);
                } else {
                  setAuctions([]);
                }
                setTotalPages(Math.ceil(res.data.total / pageInfo.size));
            })
            .catch((err) => {
                console.error(err);
            });
    }, [pageInfo.size]);

    useEffect(() => {
      fetchAuctions(pageInfo.page, searchText);
    }, [pageInfo.page, searchText, fetchAuctions]);

    useEffect(() => {
        const queryParams = new URLSearchParams(location.search);
        const sortOrderFromUrl = queryParams.get("sortOrder");
        const pageFromUrl = queryParams.get("page");

        if (sortOrderFromUrl) {
            setSortOrder(sortOrderFromUrl);
        }

        if (pageFromUrl) {
            setPageInfo(prev => ({...prev, page: parseInt(pageFromUrl)}));
        }
    }, [location]);

    const handleSearch = useCallback((newSearchText) => {
        setSearchText(newSearchText);
        setPageInfo(prev => ({...prev, page: 1}));
    }, []);

    const updateUrlParams = useCallback((sortOrder, page) => {
        const queryParams = new URLSearchParams();
        if (sortOrder) queryParams.set("sortOrder", sortOrder);
        if (page) queryParams.set("page", page.toString());
        navigate({
            search: queryParams.toString(),
        });
    }, [navigate]);

    const handlePageChange = useCallback((newPage) => {
        setPageInfo(prev => ({...prev, page: newPage}));
        updateUrlParams(sortOrder, newPage);
    }, [sortOrder, updateUrlParams]);

    const sortedAuctions = auctions.sort((a, b) => new Date(a.startTime) - new Date(b.startTime));

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
              <CardTitle tag="h5">경매 목록</CardTitle>
              <Search onSearch={handleSearch} />
            </div>
            <Table className="no-wrap mt-3 align-middle" responsive borderless>
              <thead>
                <tr>
                  <th>상품명</th>
                  <th>판매가격</th>
                  <th>시작시간</th>
                  <th>종료시간</th>
                  <th>시작가격</th>
                  <th>낙찰가격</th>
                  <th>낙찰자</th>
                  <th>경매 진행 상황</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {sortedAuctions.map((auction) => (
                  <tr key={auction.auctionId} className="border-top">
                    <td>
                      <div className="d-flex align-items-center p-2">
                        <div className="ms-3">
                          <h6 className="mb-0">{auction.shopName}</h6>
                        </div>
                      </div>
                    </td>
                    <td>{auction.shopPrice}</td>
                    <td>
                      {" "}
                      {new Date(auction.startTime)
                        .toLocaleString("ko-KR", {
                          year: "2-digit",
                          month: "2-digit",
                          day: "2-digit",
                          hour: "2-digit",
                          minute: "2-digit",
                          hour12: false, // 24시간 형식
                        })
                        .replace(/\//g, "-")
                        .replace(",", "")}{" "}
                    </td>
                    <td>{auction.endTime}</td>
                    <td>{auction.startPrice}</td>
                    <td>{auction.endPrice}</td>
                    <td>나</td>
                    <td>
                      {auction.auctionStatus === 0 && "시작전"}
                      {auction.auctionStatus === 1 && "진행중"}
                      {auction.auctionStatus === 2 && "종료"}
                    </td>
                    <td>
                      <button
                        onClick={() =>
                          navigate(`/admin/shopdetailform/${auction.shopId}`)
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
            onPrev={() => handlePageChange(Math.max(pageInfo.page - 1, 1))}
            onNext={() =>
              handlePageChange(Math.min(pageInfo.page + 1, totalPages))
            }
          />
        </Card>
      </div>
    );
};

export default AuctionsTables;