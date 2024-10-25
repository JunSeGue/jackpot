package com.bitcamp.jackpot.domain;

import com.bitcamp.jackpot.dto.ReviewDTO;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Review extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer reviewId;
    @Column(length = 50, nullable = false)
    private String content;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="shopId", referencedColumnName = "shopId")
    private Shop shop;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="memberId", referencedColumnName = "memberId")
    private Member member;
    public void updateFromDTO(ReviewDTO reviewDTO) {
        this.content = reviewDTO.getContent();
        this.member = Member.builder().memberId(reviewDTO.getMemberId()).build();
        this.shop = Shop.builder().shopId(reviewDTO.getShopId()).build();
    }
}
