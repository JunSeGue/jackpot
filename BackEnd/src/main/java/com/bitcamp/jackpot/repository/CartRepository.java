package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Cart;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CartRepository extends JpaRepository<Cart, Integer> {
    List<Cart> findByMemberEmail(String email);

    @Query("SELECT c From Cart c where c.member.email = :email")
    List<Cart> findAllByMemberEmail(String email);
}
