package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Auction;
import com.bitcamp.jackpot.domain.Bidding;
import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.dto.BiddingDTO;
import com.bitcamp.jackpot.jwt.CustomUserDetails;
import com.bitcamp.jackpot.repository.AuctionRepository;
import com.bitcamp.jackpot.repository.BiddingRepository;
import com.bitcamp.jackpot.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Log4j2
public class BiddingServiceImpl implements BiddingService {
    private final BiddingRepository biddingRepository;
    private final MemberRepository memberRepository;
    private final AuctionRepository auctionRepository;

    private CustomUserDetails getUserDetails() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (CustomUserDetails) auth.getPrincipal();
    }

    public int findHighestBidPrice() {
        Integer highestBidPrice = biddingRepository.findHighestBidPrice();
        if (highestBidPrice == null) {
            return 0;  // 값이 없을 경우 기본값으로 0을 반환
        }
        return highestBidPrice;
    }

    public void register(BiddingDTO biddingDTO) {
        CustomUserDetails userDetails = getUserDetails();
        Member member = memberRepository.findById(biddingDTO.getMemberID())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다"));
        Auction auction = auctionRepository.findById(biddingDTO.getAuctionId())
                .orElseThrow(() -> new RuntimeException("상품을 찾을 수 없습니다"));
        Bidding bidding = dtoToEntity(biddingDTO, auction, member);
        biddingRepository.save(bidding);
    }

    @Transactional
    public void remove(int auctionId, int memberID) {
        LocalDateTime now = LocalDateTime.now();
        Member member = memberRepository.findById(memberID)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다"));
        Auction auction = auctionRepository.findById(auctionId)
                .orElseThrow(() -> new RuntimeException("상품을 찾을 수 없습니다"));
        auction.setEnd_Price(biddingRepository.findHighestBidPrice());
        auction.setAuctionStatus(2);
        auction.setEnd_Time(now);
        auction.setMember(member);
        biddingRepository.deleteAllByAuction_AuctionId(auctionId);
    }

    @Override
    public boolean isAuctionEnded(int auctionId) {
        Auction auction = auctionRepository.findById(auctionId)
                .orElseThrow(() -> new RuntimeException("상품을 찾을 수 없습니다"));
        if (auction.getAuctionStatus() == 2) {
            return true;
        }
        return false;
    }

    @Override
    public BiddingDTO findLastBidder() {
        Bidding lastBidding = biddingRepository.findTopByOrderByBiddingIdDesc();
        if (lastBidding == null) {
            throw new RuntimeException("마지막 입찰을 찾을 수 없습니다.");
        }
        log.info(biddingRepository.findTopByOrderByBiddingIdDesc());
        return entityToDto(lastBidding);
    }

    public BiddingDTO findBeforeBidding(int biddingId) {
        return null;
    }
}
