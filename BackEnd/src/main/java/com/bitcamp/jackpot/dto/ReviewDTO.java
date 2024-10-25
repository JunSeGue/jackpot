package com.bitcamp.jackpot.dto;

import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Shop;
import jakarta.persistence.Column;
import jakarta.persistence.ManyToOne;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ReviewDTO {

    private Integer reviewId;
    private String content;
    private int shopId;
    private int memberId;
    private String memberName;
    private String shopName;

}
