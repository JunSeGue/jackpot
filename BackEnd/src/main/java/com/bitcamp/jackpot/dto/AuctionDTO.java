package com.bitcamp.jackpot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuctionDTO {
    private Integer auctionId;
    private int auctionStatus;
    private int startPrice;
    private int endPrice;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private int shopId;
    private int memberId;
    private String memberName;
    private String shopName;
    private String shopDetail;
    private int shopPrice;
}
