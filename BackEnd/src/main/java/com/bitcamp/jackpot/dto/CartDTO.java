package com.bitcamp.jackpot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CartDTO {

    private Integer cartId;

    private int shopId;

    private int memberId;

    private String shopName;

    private int shopPrice;

    private int quantity;
}
