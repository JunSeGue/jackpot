package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Review;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

public interface ReviewRepository extends JpaRepository<Review, Integer> {
}
