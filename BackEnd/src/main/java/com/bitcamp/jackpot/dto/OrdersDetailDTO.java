package com.bitcamp.jackpot.dto;

import lombok.*;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class OrdersDetailDTO {

    private int id;

    private LocalDateTime regDate;

    private String orderId;            // 주문 ID

    private int shopId;

    private String shopName;

    private int price;

    private int quantity;

    private int memberId;              // 회원 ID 추가

    private String name;               // 구매자 이름

    private String phone;              // 전화번호

    private String address;            // 배송지 주소

    private int deliveryState;         // 배송 상태

    private int deliveryPrice;

    private int totalPrice;
}
