package com.bitcamp.jackpot.domain;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = {"shop", "member"})
public class Auction extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int auctionId;
    @Column(name = "auction_status")
    private int auctionStatus;
    @NotNull
    @Column(name = "start_time")
    private LocalDateTime startTime;

    private LocalDateTime end_time;
    @NotNull
    private int start_price;

    private int end_price;

    @ManyToOne
    @JoinColumn(name = "shopId", referencedColumnName = "shopId")
    @JsonBackReference
    Shop shop;
    @ManyToOne
    @JoinColumn(name = "memberId", referencedColumnName = "memberId")
    @JsonBackReference
    Member member;

    @OneToMany(mappedBy = "auction", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @JsonManagedReference
    private List<Bidding> bids;
    
    public void setAuctionStatus(int auction_status) {
        this.auctionStatus = auction_status;
    }

    public void setEnd_time(LocalDateTime endTime) {
        this.end_time = endTime;
    }

    public void setEnd_Price(int endPrice) {
        this.end_price = endPrice;
    }

    public void setEnd_Time(LocalDateTime now) {
        this.end_time = now;
    }

    public void setMember(Member member) {
        this.member = member;
    }
}
