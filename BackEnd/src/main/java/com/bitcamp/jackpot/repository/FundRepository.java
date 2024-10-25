package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Dog;
import com.bitcamp.jackpot.domain.Fund;
import com.bitcamp.jackpot.domain.Member;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface FundRepository extends JpaRepository<Fund, Integer> {
    @Query("SELECT f FROM Fund f WHERE f.dog.dogId = :dogId")
    List<Fund> findFundByDogId(int dogId, Pageable pageable);

//    @Query("SELECT f FROM Fund f WHERE f.member.memberId = :memberId")
//    List<Fund> findFundByMemberId(int memberId, Pageable pageable);

     @Query("SELECT f FROM Fund f WHERE f.member.memberId = :memberId")
     List<Fund> findAllByMemberId(int memberId);

     @Query("SELECT SUM(F.collection) from Fund F WHERE F.dog.dogId = :dogId")
     Optional<Integer> findSumOfCollectionByDogId(int dogId);
//    @Query("SELECT f FROM Fund f WHERE f.member.memberId = :memberId")
//    List<Fund> findFundByMemberId(@Param("memberId") int memberId, Pageable pageable);

}
