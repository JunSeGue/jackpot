package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Orders;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface OrdersRepository extends JpaRepository<Orders, Integer> {
    Optional<Orders> findByOrderId(String orderId);

    @Query("SELECT o FROM Orders o WHERE o.member.memberId = :memberId")
    List<Orders> findAllByMemberId(int memberId);

    @Query("SELECT o From Orders o Where o.orderId = :orderId")
    List<Orders> findAllByOrderId(int orderId);

    Optional<Orders> findByOrderIdAndShop_ShopId(String orderId, int shopId);
}
