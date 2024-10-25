package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Review;
import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.ReviewDTO;

import java.util.List;
import java.util.stream.Collectors;

public interface ReviewService {
     void register(ReviewDTO reviewDTO);
     void edit(ReviewDTO reviewDTO);
     void remove(Integer reviewId);
     ReviewDTO findOne(Integer reviewId);
     List<ReviewDTO> findAll();

     default Review dtoToEntity(ReviewDTO reviewDTO) {
          Member member = Member.builder().memberId(reviewDTO.getMemberId()).build();
          Shop shop = Shop.builder().shopId(reviewDTO.getShopId()).build();
          return Review.builder()
                  .reviewId(reviewDTO.getReviewId())
                  .content(reviewDTO.getContent())
                  .member(member)
                  .shop(shop)
                  .build();
     }

     default ReviewDTO entityToDto(Review review) {
          return ReviewDTO.builder()
                  .reviewId(review.getReviewId())
                  .content(review.getContent())
                  .memberId(review.getMember() != null ? review.getMember().getMemberId() : null)  // memberId 처리
                  .shopId(review.getShop() != null ? review.getShop().getShopId() : null)  // shopId 처리
                  .memberName(review.getMember() != null ? review.getMember().getName() : null)  // memberName 처리
                  .shopName(review.getShop() != null ? review.getShop().getName() : null)  // shopName 처리
                  .build();
     }
     default List<ReviewDTO> entityListToDtoList(List<Review> reviews) {
          return reviews.stream()
                  .map(this::entityToDto)
                  .collect(Collectors.toList());
     }
}
