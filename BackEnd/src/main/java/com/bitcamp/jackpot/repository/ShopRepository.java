package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Shop;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ShopRepository extends JpaRepository<Shop, Integer> {

    @Query("SELECT s FROM Shop s WHERE s.name like %:name%")
    Page<Shop> findByShopName(@Param("name") String name, Pageable pageable);

    @Query("SELECT s FROM Shop s WHERE s.category = :category")
    Page<Shop> findByCategory(@Param("category") int category, Pageable pageable);


    @Modifying
    @Query("UPDATE Shop s SET s.buy_count = s.buy_count + :buyCount WHERE s.shopId = :shopId")
    int increaseBuyCount(@Param("shopId") int shopId, @Param("buyCount") int buyCount);
}
