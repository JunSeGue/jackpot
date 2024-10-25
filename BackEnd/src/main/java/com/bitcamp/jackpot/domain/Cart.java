package com.bitcamp.jackpot.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Cart extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int cartId;

    private Integer quantity;

    @ManyToOne
    @JoinColumn(name="shop_id")
    Shop shop;

    @ManyToOne(cascade = CascadeType.PERSIST)
    @JoinColumn(name="member_id")
    Member member;
}
