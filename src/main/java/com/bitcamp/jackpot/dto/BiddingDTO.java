package com.bitcamp.jackpot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.cglib.core.Local;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BiddingDTO {

    private int biddingId;
    private int bidPrice;
    private LocalDateTime bidTime;
    private int memberID;
    private String memberName;
    private int auctionId;
    private int auctionStatus;
}
