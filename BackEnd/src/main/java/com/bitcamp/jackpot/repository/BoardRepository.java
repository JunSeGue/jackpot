package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Board;
import com.bitcamp.jackpot.domain.Member;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface BoardRepository extends JpaRepository<Board, Integer> {
    //@Query(SELECT b FROM Board b)
//    Page<Board> findAll(Pageable pageable);
    List<Board> findByType(Integer type); // type에 따라 게시글 검색

    @Query("SELECT COALESCE(MAX(b.boardId), 0) FROM Board b")
    int findMaxBoardId();
    // 서비스단에서 포스트ID 숫자 +1해주려고 기존 포스트ID를 알아오는 쿼리문.

//    @Query("SELECT b FROM Board b WHERE LOWER(b.title) LIKE LOWER(CONCAT('%', :keyword, '%'))")
//    Page<Board> searchByTitle(@Param("keyword") String keyword);
//    Page<Board> searchByTitle(@Param("keyword") String keyword, Pageable pageable);

//    Page<Board> findByTitleContainingIgnoreCase(String keyword);
    Page<Board> findByTitleContainingIgnoreCase(String keyword, Pageable pageable);
    // 위 메서드명 사용시 쿼리문 안적어도 자동으로 쿼리문을 생성함
    // 대소문자 구분 없이 받아온 키워드로 제목 검색함. 검색결과는 리스트에 저장해서 반환함.

    @Query("SELECT b FROM Board b WHERE b.member.memberId = :memberId")
    Page<Board> findByMemberId(@Param("memberId") int memberId, Pageable pageable);

}

