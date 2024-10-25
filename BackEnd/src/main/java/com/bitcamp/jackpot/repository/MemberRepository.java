package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Member;
import lombok.NonNull;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNullApi;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Integer> {
    Optional<Member> findByEmail(String email);

    Boolean existsByEmail(String email);

    Boolean existsByNickName(String nickName);

    Optional<Member> findByNameAndPhone(String name, String phone);

    void deleteByEmail(String email);
    Page<Member> findByNameContaining(String name, Pageable pageable);

}