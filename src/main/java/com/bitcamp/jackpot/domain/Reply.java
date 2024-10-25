package com.bitcamp.jackpot.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Reply extends BaseEntity{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(updatable = false, unique = true)
    private int replyId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="memberId", referencedColumnName = "memberId")
    private Member member;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "boardId",  referencedColumnName = "boardId")
    private Board board;

    @Column(nullable = false, length = 50)
    private String content;

    @Column // (nullable = false)
    private LocalDateTime regDate;

    // 댓글 등록 전에 regDate 자동 설정
    @PrePersist
    public void prePersist() {
        this.regDate = LocalDateTime.now();
    }
}


