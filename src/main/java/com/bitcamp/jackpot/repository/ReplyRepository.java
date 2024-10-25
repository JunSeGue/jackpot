package com.bitcamp.jackpot.repository;

import com.bitcamp.jackpot.domain.Reply;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ReplyRepository extends JpaRepository<Reply, Integer> {

//    List<Reply> findAllByBoardId(Integer boardId);


    @Query("SELECT r FROM Reply r WHERE r.board.boardId = :boardId")
    List<Reply> findAllByBoardId(Integer boardId);

    @Query("SELECT COALESCE(MAX(b.replyId), 0) FROM Reply b")
    int findMaxReplyId();
    
    // 아래 메서드 두개는 글 삭제시 거기 달린 댓글들도 같이 삭제되게 하기 위한 메서드
    @Query("SELECT COUNT(r) > 0 FROM Reply r WHERE r.board.boardId = :boardId")
    boolean existsByBoardId(Integer boardId);

    @Modifying
    @Query("DELETE FROM Reply r WHERE r.board.boardId = :boardId")
    void deleteByBoardId(@Param("boardId") Integer boardId);
}
