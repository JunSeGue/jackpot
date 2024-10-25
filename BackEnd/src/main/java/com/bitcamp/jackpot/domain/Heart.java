package com.bitcamp.jackpot.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Heart extends BaseEntity{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int heartId;

    @ManyToOne(fetch = FetchType.LAZY)
    private Member memberId;

    @ManyToOne(fetch = FetchType.LAZY)
    private Dog dogId;
}
