package com.bitcamp.jackpot.domain;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Entity
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Shop extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "shopId")
    private int shopId;

    @Column(length = 20, nullable = false)
    private String name;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String detail;

    @Column(nullable = false)
    private int category;

    @Column(nullable = false)
    private int price;

    private int buy_count;
    private int cell_count;

    @Column(nullable = false)
    private String mainImage;

    @Column(nullable = false)
    private String detailImage1;

    @Column(nullable = false)
    private String detailImage2;

    @Column(nullable = false)
    private String detailImage3;

    @Column(nullable = false)
    private String detailImage4;

    @OneToMany(mappedBy = "shop", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<Review> reviews;
    @OneToMany(mappedBy = "shop", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<Cart> carts;
    @OneToMany(mappedBy = "shop", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<Orders> orders;
    @OneToMany(mappedBy = "shop", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @JsonManagedReference
    private List<Auction> auctions;


}