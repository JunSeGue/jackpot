import React, { useEffect, useState } from "react";
import axios from "axios";

function Test() {
    const [cart, setCart] = useState([]);
    const [memberId, setMemberId] = useState(1);
    const [shopId, setShopId] = useState(3);
    const [carts, setCarts] = useState([]);
    // const [review, setReview] = useState({
    //     reviewId: '',
    //     content: '',
    //     memberName: '',
    //     shopName: ''
    // });

    const addCart = () => {
        axios.post("http://localhost:8181/cart/register", {
            memberId: memberId,
            shopId: shopId
        })
            .then(response => {
                console.log('카트가 저장되었습니다.');
            })
            .catch(error => {
                console.error('카트 저장 중 오류 발생:', error);
            });
    };

    useEffect(() => {
        axios.get("http://localhost:8181/cart/findall", {
        })
            .then(res => {
                setCarts(res.data);
                console.log('불러오기 성공');
            })
            .catch(e => {
                console.log('실패', e);
            });
    }, []); // 의존성 배열이 빈 경우, useEffect가 컴포넌트 마운트 시 한 번만 호출됨

    // const handleChange = (e) => {
    //     const { name, value } = e.target;
    //     setReview(prev => ({
    //         ...prev,
    //         [name]: value
    //     }));
    // };

    const editCart = () => {
        axios.post("http://localhost:8181/cart/edit", cart)
            .then(response => {
                console.log('리뷰가 수정되었습니다.');
            })
            .catch(error => {
                console.error('리뷰 수정 중 오류 발생:', error);
            });
    };

    const removeCart = () => {
        axios.delete("http://localhost:8181/cart/remove", {
            params:{
                cartId: 1
            }
        })
            .then(res => {
                console.log("삭제 완료")
            }).catch(e => {
                console.error(e)
        })
    }

    return (
        <>
            <button type='button' onClick={addCart}>카트추가</button>

            {carts.map(carts => (
                <div key={carts.id}>
                    <p>카트Id : {carts.cartId}</p>
                    <p>이름 : {carts.shopName}</p>
                    <p>가격 : {carts.shopPrice}</p>
                    <p>등록자Id : {carts.memberId}</p>
                </div>
            ))}

            <button type='button' onClick={removeCart}>삭제</button>
        </>
    );
}

export default Test;
