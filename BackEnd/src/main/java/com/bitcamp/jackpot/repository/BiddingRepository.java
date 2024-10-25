package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Bidding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface BiddingRepository extends JpaRepository<Bidding, Integer> {

    void deleteAllByAuction_AuctionId(int auctionId);

    @Query("SELECT MAX(b.bid_price) FROM Bidding b")
    Integer findHighestBidPrice();

    Bidding findTopByOrderByBiddingIdDesc();
}
