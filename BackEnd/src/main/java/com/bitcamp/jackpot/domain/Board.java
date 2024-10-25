    package com.bitcamp.jackpot.domain;

    import com.fasterxml.jackson.annotation.JsonBackReference;
    import com.fasterxml.jackson.annotation.JsonIdentityInfo;
    import com.fasterxml.jackson.annotation.JsonManagedReference;
    import com.fasterxml.jackson.annotation.ObjectIdGenerators;
    import jakarta.persistence.*;
    import lombok.*;

    import java.time.LocalDateTime;

    @Entity
    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public class Board extends BaseEntity {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        @Column(updatable = false, unique = true)
        private int boardId;

        @Column(length = 20)
        private String title;

        @Column(length = 100)
        private String content;

        @Column
        private LocalDateTime regDate;

        @Column
        private int type;

        @ManyToOne(fetch = FetchType.EAGER)
        @JoinColumn(name = "memberId", referencedColumnName = "memberId")
        private Member member;

        public void edit(String title, String content) {
            this.title = title;
            this.content = content;
        }
    }
