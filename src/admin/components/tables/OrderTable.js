import React, {useEffect, useState} from "react";
import {useNavigate} from "react-router-dom";
import {Card, CardBody, CardTitle, Table} from "reactstrap";
import apiClient from "../../../token/AxiosConfig";
import styled from "styled-components";

const OrderTables = () => {
    const navigate = useNavigate();
    const [orders, setOrders] = useState([]);

    const fetchOrders = () => {
        apiClient
            .get('order/findAll')
            .then((res) => {
                console.log(res.data);
                if (Array.isArray(res.data)) {
                    setOrders(res.data);
                    console.log("orders : " + orders);
                }
            })
            .catch((err) => {
                console.error(err);
            })
    }
    const handleDeliveryStateChange = (newState, order) => {
        const ordersDTO = {
            orderId : order.orderId,
            deliveryState: newState, // 새로운 배송 상태
            shopId: order.shopId
        };

        apiClient
            .post(`/order/edit`, ordersDTO)
            .then((response) => {
                console.log("배송 상태 업데이트 성공:", response.data);
                alert("배송상태가 변경되었습니다.");
                window.location.reload();
            })
            .catch((error) => {
                console.error("배송 상태 업데이트 실패:", error);
            });
    };

    useEffect(() => {
        fetchOrders();
    }, []);

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
                    </div>
                    <Table className="no-wrap mt-3 align-middle" responsive borderless>
                        <thead>
                        <tr>
                            <th>구매자</th>
                            <th>상품명</th>
                            <th>가격</th>
                            <th>구매수량</th>
                            <th>배송상태</th>
                            <th></th>
                        </tr>
                        </thead>
                        <tbody>
                        {orders.map((order) => (
                            <tr key={order.orderId} className="border-top">
                                <td>
                                    <div className="d-flex align-items-center p-2">
                                        <div className="ms-3">
                                            <h6 className="mb-0">{order.name}</h6>
                                        </div>
                                    </div>
                                </td>
                                <td>{order.shopName}</td>
                                <td>{order.shopPrice}</td>
                                <td>{order.quantity}</td>
                                <td>
                                    <select
                                        value={order.deliveryState}
                                        onChange={(e) => handleDeliveryStateChange(e.target.value, order)}
                                    >
                                        <option value={0}>배송전</option>
                                        <option value={1}>배송중</option>
                                        <option value={2}>배송완료</option>
                                        <option value={4}>주문취소</option>
                                    </select>
                                </td>
                            </tr>
                        ))}
                        </tbody>
                    </Table>
                </CardBody>
            </Card>
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

export default OrderTables;
