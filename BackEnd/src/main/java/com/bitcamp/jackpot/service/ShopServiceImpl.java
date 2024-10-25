package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.*;
import com.bitcamp.jackpot.jwt.CustomUserDetails;
import com.bitcamp.jackpot.repository.MemberRepository;
import com.bitcamp.jackpot.repository.OrdersRepository;
import com.bitcamp.jackpot.repository.ShopRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
@Log4j2
public class ShopServiceImpl implements ShopService {


    private final ShopRepository shopRepository;
    private final ModelMapper modelMapper;
    private final MemberRepository memberRepository;
    private final OrdersRepository ordersRepository;

    // 로그인된 사용자 정보를 가져오는 메서드
    private CustomUserDetails getUserDetails() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (CustomUserDetails) auth.getPrincipal();
    }

    @Override
    public void register(ShopDTO shopDTO) {
        CustomUserDetails userDetails = getUserDetails();
        Member member = memberRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        shopDTO.setCell_count(0);
        Shop shop = modelMapper.map(shopDTO, Shop.class);
        shopRepository.save(shop);
    }

    @Override
    public void edit(int shopId, ShopDTO shopDTO) {
        log.info(shopDTO);
        CustomUserDetails userDetails = getUserDetails();
        Shop shop = shopRepository.findById(shopId)
                .orElseThrow(() -> new RuntimeException("해당 상품을 찾을 수 없습니다."));
        modelMapper.map(shopDTO, shop);
        shopRepository.save(shop);
    }

    @Override
    public void remove(int shopId) {
        CustomUserDetails userDetails = getUserDetails();
        Shop shop = shopRepository.findById(shopId)
                .orElseThrow(() -> new RuntimeException("해당 상품을 찾을 수 없습니다."));
        shopRepository.deleteById(shopId);
    }

    @Override
    public void addBuyCount(int shopId, int buyCount) {
        shopRepository.increaseBuyCount(shopId, buyCount);
    }

    @Override
    public ShopDTO findOne(int shopId) {
        Shop shop = shopRepository.findById(shopId)
                .orElseThrow(() -> new RuntimeException("해당 상품을 찾을 수 없습니다."));
        return modelMapper.map(shop, ShopDTO.class);
    }

    @Override
    public PageResponseDTO<ShopDTO> findListAdmin(PageRequestDTO pageRequestDTO) {
        Pageable pageable = pageRequestDTO.getPageable("shopId");
        Page<Shop> result = shopRepository.findAll(pageable);
        List<ShopDTO> shopDTOList = result.getContent().stream()
                .map(shop -> modelMapper.map(shop, ShopDTO.class))
                .collect(Collectors.toList());
        return new PageResponseDTO<>(pageRequestDTO, shopDTOList, (int) result.getTotalElements());
    }

    @Override
    public PageResponseDTO<ShopDTO> findList(PageRequestDTO pageRequestDTO) {

        Pageable pageable = pageRequestDTO.getPageable("shopId");

        Page<Shop> result = shopRepository.findAll(pageable);


        List<ShopDTO> shopDTOList = result.getContent().stream()
                .map(shop -> modelMapper.map(shop, ShopDTO.class))
                .collect(Collectors.toList());

        int totalElements = (int) result.getTotalElements(); // 전체 요소 수
        int totalPages = result.getTotalPages(); // 전체 페이지 수

        return new PageResponseDTO<>(pageRequestDTO, shopDTOList, totalPages);
    }


    @Override
    public PageResponseDTO<ShopDTO> search(String name, PageRequestDTO pageRequestDTO) {
//        log.info(name);
//        log.info(pageRequestDTO.toString());

        Pageable pageable = pageRequestDTO.getPageable("shopId");
        Page<Shop> result = shopRepository.findByShopName(name, pageable);

//        log.info(pageable);
//        log.info(result);

        List<ShopDTO> shopDTOList = result.getContent().stream()
                .map(shop -> modelMapper.map(shop, ShopDTO.class))
                .collect(Collectors.toList());
//        log.info(shopDTOList);
        return new PageResponseDTO<>(pageRequestDTO, shopDTOList, (int) result.getTotalElements());
    }

    @Override
    public PageResponseDTO<ShopDTO> findByCategory(int category, PageRequestDTO pageRequestDTO) {
        Pageable pageable = pageRequestDTO.getPageable("shopId");
        Page<Shop> result = shopRepository.findByCategory(category, pageable);
        List<ShopDTO> shopDTOList = result.getContent().stream()
                .map(shop -> modelMapper.map(shop, ShopDTO.class))
                .collect(Collectors.toList());

        return new PageResponseDTO<>(pageRequestDTO, shopDTOList, (int) result.getTotalElements());
    }

    @Override
    public List<OrdersDTO> findOrderList(PageRequestDTO pageRequestDTO) {
//        CustomUserDetails ud = getUserDetails();
//        Optional<Member> oMember = memberRepository.findByEmail(ud.getUsername());
//        Member member = oMember.orElseThrow();
//        int memberId = member.getMemberId();
//
//        Pageable pageable = pageRequestDTO.getPageable("orderId");
////        log.info(memberId);
////        Page<Orders> result = ordersRepository.findByMemberId(memberId, pageable);
//        List<OrdersDTO> ordersDTOList = result.getContent().stream()
//                .map(order -> modelMapper.map(order, OrdersDTO.class)) // 수정된 부분
//                .collect(Collectors.toList());
//        log.info(ordersDTOList);
//        return ordersDTOList;
        return null;
    }
}
