package com.bitcamp.jackpot.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Builder
@Getter
@Setter
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
@NoArgsConstructor
public class Orders extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(name = "orderId", nullable = false)
    private String orderId;

    @Column(nullable = false)
    private int quantity;

    private int delivery_state;

    @Column(nullable = false)
    private int totalPrice;

    @ManyToOne
    @JoinColumn(name = "shop_id", nullable = false)
    @JsonIgnore
    private Shop shop;
    @ManyToOne
    @JoinColumn(name = "member_id", nullable = false)
    private Member member;

    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime regDate;

    public void setDelivery_state(int delivery_state) {
        this.delivery_state = delivery_state;
    }
}