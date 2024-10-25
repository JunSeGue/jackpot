import React, {useEffect, useState} from "react";
import styled from "styled-components";
import apiClient from "../../token/AxiosConfig";


const StockForm = ({shopId}) => {
    // console.log(shopId);
    const [shop, setShop] = useState([]);
    const [buy_count, setBuyCount] = useState(null);


    useEffect(() => {
        apiClient.get(`admin/shop/findOne/${shopId}`)
            .then(res => {
                setShop(res.data);
                // console.log(res.data);
            })
            .catch(err => {
                console.log(err);
            })
    }, [shopId]);

    const handleBuyCountChange = (e) => {
        const value = e.target.value;
        if (isNaN(value)) {
            alert("숫자만 입력 가능합니다!");
            e.target.value = "";
            return;
        }
        setBuyCount(value); // 입력된 값이 숫자일 때만 상태 업데이트
    };
    const addBuyCount = (e) => {
        e.preventDefault(); // 기본 폼 제출 이벤트 방지
        apiClient.post(`admin/shop/buycount/${shopId}`, buy_count, {
            headers: {
                "Content-Type": 'application/json'
            }
        })
            .then((res) => {
                console.log(res.data);
                window.location.reload();
            })
            .catch((err) => {
                console.error(err);
            });
    }
    return (
        <StyledWrapper>
            <form className="form" onSubmit={addBuyCount}>
                <p className="form-title">매입 관리</p>
                <p>현재 재고 : {shop.buy_count - shop.cell_count}</p>
                <div className="input-container">
                    <p>판매 수량 : {shop.cell_count}</p>
                </div>
                <div className="input-container">
                    <input
                        type="input"
                        placeholder="매입 수량"
                        name="buy_count"
                        value={buy_count} // 상태 값으로 입력 필드 설정
                        onChange={handleBuyCountChange} // 핸들러 추가
                    />
                    <span></span>
                </div>
                <button type="submit" className="submit">
                    매입 등록
                </button>
            </form>
        </StyledWrapper>
    );
};

const StyledWrapper = styled.div`
  .form {
    background-color: #fff;
    display: block;
    padding: 1rem;
    width: 100%; /* 100% 너비를 유지 */
    border-radius: 0.5rem;
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
  }

  .form-title {
    font-size: 1.25rem;
    line-height: 1.75rem;
    font-weight: 600;
    text-align: center;
    color: #000;
  }

  .input-container {
    position: relative;
  }

  .input-container input, .form button {
    outline: none;
    border: 1px solid #e5e7eb;
    margin: 8px 0;
  }

  .input-container input {
    background-color: #fff;
    padding: 1rem;
    padding-right: 3rem;
    font-size: 0.875rem;
    line-height: 1.25rem;
    width: 300px;
    border-radius: 0.5rem;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
  }

  .submit {
    display: block;
    padding-top: 0.75rem;
    padding-bottom: 0.75rem;
    padding-left: 1.25rem;
    padding-right: 1.25rem;
    background-color: #4F46E5;
    color: #ffffff;
    font-size: 0.875rem;
    line-height: 1.25rem;
    font-weight: 500;
    width: 100%;
    border-radius: 0.5rem;
    text-transform: uppercase;
  }

  .signup-link {
    color: #6B7280;
    font-size: 0.875rem;
    line-height: 1.25rem;
    text-align: center;
  }

  .signup-link a {
    text-decoration: underline;
  }
`;

export default StockForm;
