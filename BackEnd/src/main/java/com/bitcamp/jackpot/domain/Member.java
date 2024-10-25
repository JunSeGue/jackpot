package com.bitcamp.jackpot.domain;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;

@Entity
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Member extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int memberId;

    @Column(length = 20, nullable = false)
    private String name;

    @Column(length = 30, nullable = false, unique = true)
    private String email;

    private String pwd;

    @Column(length = 20, nullable = false)
    private String phone;

    @Column(length = 10, nullable = false, unique = true)
    private String nickName;

    @Column(length = 100, nullable = false)
    private String address;

    @Builder.Default
    @Column(nullable = false)
    private int grade = 1;

    //비밀번호 인코딩 메서드
    public void encodePassword(String rawPassword, BCryptPasswordEncoder encoder) {
        this.pwd = encoder.encode(rawPassword);
    }

    public Member changePassword(String newPassword, BCryptPasswordEncoder passwordEncoder) {
        this.pwd = passwordEncoder.encode(newPassword);
        return this;
    }

    @OneToMany(mappedBy = "member", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<Review> reviews;

    @OneToMany(mappedBy = "member", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<Orders> orders;

    @OneToMany(mappedBy = "member", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<Cart> carts;

    @OneToMany(mappedBy = "member", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @JsonManagedReference
    private List<Auction> auctions;

    @OneToMany(mappedBy = "member", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<Board> boards;

    @OneToMany(mappedBy = "member", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @JsonManagedReference
    private List<Bidding> bids;

    public void updateMemberInfo(String name, String phone, String pwd, String address) {
        this.name = name;
        this.phone = phone;
        this.pwd = pwd;
        this.address = address;
    }

    public void updateMemberGrade(int grade) {
        this.grade = grade;
    }

}