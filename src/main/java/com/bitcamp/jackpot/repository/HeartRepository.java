package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Dog;
import com.bitcamp.jackpot.domain.Heart;
import com.bitcamp.jackpot.domain.Member;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface HeartRepository extends JpaRepository<Heart, Integer> {

    @Query("select h from Heart h where h.dogId = :dog and h.memberId = :member")
    public Optional<Heart> findByDogIdAndMemberId(Dog dog, Member member);

    public Page<Heart> findByDogId(Dog dog, Pageable pageable);

    public Page<Heart> findByMemberId(Member member, Pageable pageable);

    Optional <Heart> deleteByMemberId(Member member);
}
