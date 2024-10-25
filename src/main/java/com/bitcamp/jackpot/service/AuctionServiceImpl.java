package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Auction;
import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.AuctionDTO;
import com.bitcamp.jackpot.jwt.CustomUserDetails;
import com.bitcamp.jackpot.dto.PageRequestDTO;
import com.bitcamp.jackpot.dto.PageResponseDTO;
import com.bitcamp.jackpot.repository.AuctionRepository;
import com.bitcamp.jackpot.repository.MemberRepository;
import com.bitcamp.jackpot.repository.ShopRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class AuctionServiceImpl implements AuctionService {
    private final ModelMapper modelMapper;
    private final MemberRepository memberRepository;
    private final AuctionRepository auctionRepository;
    private final ShopRepository shopRepository;

    private AuctionDTO checkAuction(Auction auction) {
        LocalDateTime now = LocalDateTime.now();
        Auction ongoingAuction = auctionRepository.findOngoingAuction();
        if (ongoingAuction != null) {
            return entityToDto(ongoingAuction);
        }
        Auction upcomingAuction = auctionRepository.findUpcomingAuction(now);

        return entityToDto(upcomingAuction);
    }

    // 로그인된 사용자 정보를 가져오는 메서드
    private CustomUserDetails getUserDetails() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (CustomUserDetails) auth.getPrincipal();
    }

    @Override
    public AuctionDTO register(AuctionDTO auctionDTO, int shopId) {
        CustomUserDetails userDetails = getUserDetails();
        Member member = memberRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다"));
        Shop shop = shopRepository.findById(shopId)
                .orElseThrow(() -> new RuntimeException("상품을 찾을 수 없습니다"));
        auctionDTO.setAuctionStatus(0);
        Auction auction = dtoToEntity(auctionDTO, shop);
        auctionRepository.save(auction);

        return checkAuction(auction);
    }

    @Override
    public AuctionDTO edit(int auctionId, int auctionStatus) {
        CustomUserDetails userDetails = getUserDetails();
        Member member = memberRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다"));
        Auction auction = auctionRepository.findById(auctionId)
                .orElseThrow(() -> new RuntimeException("해당 상품을 찾을 수 없습니다."));
        auction.setAuctionStatus(auctionStatus);
        auctionRepository.save(auction);
        return entityToDto(auction);
    }

    @Override
    public void remove(Integer auctionId) {
        CustomUserDetails userDetails = getUserDetails();
        Member member = memberRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다"));
        auctionRepository.deleteById(auctionId);
    }


    @Override
    public AuctionDTO findOne(int auctionId) {
        CustomUserDetails userDetails = getUserDetails();
        Member member = memberRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다"));
        Auction auction = auctionRepository.findById(auctionId)
                .orElseThrow(() -> new RuntimeException("auction not found"));
        AuctionDTO auctionDTO = modelMapper.map(auction, AuctionDTO.class);
        return auctionDTO;
    }

    //    @Override
//    public AuctionDTO findNextAuction() {
//        LocalDateTime currentTime = LocalDateTime.now();
//        Pageable pageable = PageRequest.of(0, 1);
//        List<Auction> auction = auctionRepository.findNextAuction(pageable, currentTime);
//        if (auction == null) {
//            return null; // 경매가 없으면 null 반환
//        }
//        AuctionDTO auctionDTO = entityToDto(auction.get(0));
//        log.info(auctionDTO);
//        return auctionDTO;
//    }

    @Override
    public AuctionDTO getAuction() {
        LocalDateTime now = LocalDateTime.now();
        Auction ongoingAuction = auctionRepository.findOngoingAuction();
        Auction upcomingAuction = auctionRepository.findUpcomingAuction(now);
        if (ongoingAuction != null) {
            return checkAuction(ongoingAuction);
        }
        return checkAuction(upcomingAuction);
    }

    @Override
    public PageResponseDTO<AuctionDTO> findAll(PageRequestDTO pageRequestDTO) {

        Pageable pageable = pageRequestDTO.getPageable("auctionId");
        Page<Auction> result = auctionRepository.findAll(pageable);
        // Page 객체에서 DTO로 변환
        List<AuctionDTO> auctionDTOList = result.getContent().stream()
                .map(this::entityToDto)
                .collect(Collectors.toList());
        // Page 정보를 그대로 사용해 PageResponseDTO를 생성
        return new PageResponseDTO<>(pageRequestDTO, auctionDTOList, (int) result.getTotalElements());
    }
}
