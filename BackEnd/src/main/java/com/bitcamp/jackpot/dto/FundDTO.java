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
public class FundDTO {
    private int fundId;

    private String orderId;

    private int dogId;

    private int memberId;

    private int collection;

    private LocalDateTime regDate;
}