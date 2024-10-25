package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Auction;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface AuctionRepository extends JpaRepository<Auction, Integer> {
    @Query(value = "SELECT * FROM auction WHERE auction_status = 1 LIMIT 1", nativeQuery = true)
    Auction findOngoingAuction();


    @Query(value = "SELECT * FROM auction WHERE start_time > :now AND auction_status = 0 ORDER BY start_time ASC LIMIT 1", nativeQuery = true)
    Auction findUpcomingAuction(@Param("now") LocalDateTime now);

}
