import React, { useState, useEffect, useCallback } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Card, CardBody, CardTitle, Table } from "reactstrap";
import Button from "../button/ShopButton";
import apiClient from "../../../token/AxiosConfig";
import Search from "../Search";
import styled from "styled-components";
import StockForm from "../StockForm";
import PageComponent from "../../../dogList/PageComponent";

const ShopTables = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [shops, setShops] = useState([]);
  const [searchText, setSearchText] = useState("");
  const [pageInfo, setPageInfo] = useState({
    page: 1,
    size: 9,
  });
  const [totalPages, setTotalPages] = useState(1);
  const [sortOrder, setSortOrder] = useState("latest");
  const [isModalOpen, setModalOpen] = useState(false);
  const [currentShopId, setCurrentShopId] = useState(null);

  const fetchShops = useCallback(
    (page, search = "") => {
      const endpoint = search
        ? `/admin/shop/search/${search}`
        : `/admin/shop/findList`;
      apiClient
        .get(endpoint, {
          params: { page: page, size: pageInfo.size },
        })
        .then((res) => {
          if (Array.isArray(res.data.dtoList)) {
            console.log(res.data);
            setShops(res.data.dtoList);
          } else {
            setShops([]);
          }
          setTotalPages(Math.ceil(res.data.total / pageInfo.size));
        })
        .catch((err) => {
          console.error(err);
        });
    },
    [pageInfo.size]
  );

  useEffect(() => {
    fetchShops(pageInfo.page, searchText);
  }, [pageInfo.page, searchText, fetchShops]);

  useEffect(() => {
    const queryParams = new URLSearchParams(location.search);
    const sortOrderFromUrl = queryParams.get("sortOrder");
    const pageFromUrl = queryParams.get("page");

    if (sortOrderFromUrl) {
      setSortOrder(sortOrderFromUrl);
    }

    if (pageFromUrl) {
      setPageInfo((prev) => ({ ...prev, page: parseInt(pageFromUrl) }));
    }
  }, [location]);

  const handleSearch = useCallback((newSearchText) => {
    setSearchText(newSearchText);
    setPageInfo((prev) => ({ ...prev, page: 1 }));
  }, []);

  const updateUrlParams = useCallback(
    (sortOrder, page) => {
      const queryParams = new URLSearchParams();
      if (sortOrder) queryParams.set("sortOrder", sortOrder);
      if (page) queryParams.set("page", page.toString());
      navigate({
        search: queryParams.toString(),
      });
    },
    [navigate]
  );

  const handlePageChange = useCallback(
    (newPage) => {
      setPageInfo((prev) => ({ ...prev, page: newPage }));
      updateUrlParams(sortOrder, newPage);
    },
    [sortOrder, updateUrlParams]
  );

  const handleOpenModal = (shopId) => {
    setCurrentShopId(shopId);
    setModalOpen(true);
  };

  const handleCloseModal = () => {
    setCurrentShopId(null);
    setModalOpen(false);
  };

  const Modal = ({ children, onClose }) => (
    <ModalOverlay onClick={onClose}>
      <ModalContent onClick={(e) => e.stopPropagation()}>
        <button
          onClick={onClose}
          style={{ border: "none", background: "none" }}
        >
          <i className="bi bi-x-circle"></i>
        </button>
        {children}
      </ModalContent>
    </ModalOverlay>
  );

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
            <CardTitle tag="h5">상품 목록</CardTitle>
            <Search onSearch={handleSearch} />
            <Button />
          </div>
          <Table className="no-wrap mt-3 align-middle" responsive borderless>
            <thead>
              <tr>
                <th>상품명</th>
                <th>가격</th>
                <th>재고</th>
                <th>카테고리</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {shops.map((shop) => (
                <tr key={shop.shopId} className="border-top">
                  <td>
                    <div className="d-flex align-items-center p-2">
                      <div className="ms-3">
                        <h6 className="mb-0">{shop.name}</h6>
                      </div>
                    </div>
                  </td>
                  <td>{shop.price}</td>
                  <td>{shop.buy_count - shop.cell_count}개</td>
                  <td>
                    {shop.category === 0 && "식품"}
                    {shop.category === 1 && "장난감"}
                    {shop.category === 2 && "가구"}
                    {shop.category === 3 && "개모차"}
                  </td>
                  <td>
                    <button
                      onClick={() =>
                        navigate(`/admin/shopdetailform/${shop.shopId}`)
                      }
                      style={{ border: "none", background: "white" }}
                    >
                      상세보기
                    </button>
                    |
                    <button
                      onClick={() => handleOpenModal(shop.shopId)}
                      style={{ border: "none", background: "white" }}
                    >
                      매입등록
                    </button>
                    |
                    <button
                      onClick={() =>
                        navigate(`/admin/auctionaddform/${shop.shopId}`)
                      }
                      style={{ border: "none", background: "white" }}
                    >
                      경매 등록
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
      {isModalOpen && (
        <Modal onClose={handleCloseModal}>
          <StockForm key={currentShopId} shopId={currentShopId} />
        </Modal>
      )}
    </div>
  );
};

const ModalOverlay = styled.div`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(255, 255, 255, 0.5);
  backdrop-filter: blur(2px);
  display: flex;
  align-items: center;
  justify-content: center;
`;

const ModalContent = styled.div`
  background-color: white;
  border-radius: 0.5rem;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
`;

export default ShopTables;
