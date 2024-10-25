package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.*;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface DogRepository extends JpaRepository<Dog, Integer> {
    //memberID로 heart누른 dog 가져오는 메서드
    @Query("select dog From Dog dog join Heart heart on heart.dogId = dog where heart.memberId = :member")
    List<Dog> findHeartDogByMemberId(@Param("member") Member member, Pageable pageable);

    //memberID로 heart안누른 dog 가져오는 메서드
    @Query("select dog From Dog dog where dog not in (select h.dogId from Heart h where h.memberId = :member)")
    List<Dog> findNotHeartDogByMemberId(@Param("member") Member member, Pageable pageable);

}
