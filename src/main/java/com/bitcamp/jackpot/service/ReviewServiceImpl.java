package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Review;
import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.ReviewDTO;
import com.bitcamp.jackpot.repository.ReviewRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Log4j2
public class ReviewServiceImpl implements ReviewService {
    private final ReviewRepository reviewRepository;

    @Override
    public void register(ReviewDTO reviewDTO) {
        log.info(reviewDTO);
        Review review = dtoToEntity(reviewDTO);
        reviewRepository.save(review);
    }

    @Override
    public void edit(ReviewDTO reviewDTO) {
//        log.info(reviewDTO);
        Review review = reviewRepository.findById(reviewDTO.getReviewId())
                .orElseThrow(() -> new RuntimeException("Review not found"));
        review.updateFromDTO(reviewDTO);

        reviewRepository.save(review);
    }

    @Override
    public void remove(Integer reviewId) {
        log.info(reviewRepository.findById(reviewId));
        reviewRepository.deleteById(reviewId);
    }

    @Override
    public ReviewDTO findOne(Integer reviewId) {
        Review review = reviewRepository.findById(reviewId)
                .orElseThrow(() -> new RuntimeException("Review not found"));
        ;
        return entityToDto(review);
    }

    @Override
    public List<ReviewDTO> findAll() {
        List<ReviewDTO> reviewDTO = entityListToDtoList(reviewRepository.findAll());
        log.info(reviewDTO);
        return reviewDTO;
    }
}
