package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Orders;
import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.OrdersDetailDTO;
import com.bitcamp.jackpot.jwt.CustomUserDetails;

import com.bitcamp.jackpot.dto.OrdersDTO;
import com.bitcamp.jackpot.repository.MemberRepository;
import com.bitcamp.jackpot.repository.OrdersRepository;
import com.bitcamp.jackpot.repository.ShopRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class OrdersServiceImpl implements OrdersService {

    private final OrdersRepository ordersRepository;
    private final ModelMapper modelMapper;
    private final MemberRepository memberRepository;
    private final ShopRepository shopRepository;

    @Override
    public void register(OrdersDTO ordersDTO) {
        log.info("Starting order registration for OrderDTO: {}", ordersDTO);

        // Shop과 Member 엔티티 조회
        Shop shop = shopRepository.findById(ordersDTO.getShopId())
                .orElseThrow(() -> {
                    log.error("Shop not found for shopId: {}", ordersDTO.getShopId());
                    return new RuntimeException("Shop not found");
                });

        Member member = memberRepository.findById(ordersDTO.getMemberId())
                .orElseThrow(() -> {
                    log.error("Member not found for memberId: {}", ordersDTO.getMemberId());
                    return new RuntimeException("Member not found");
                });

        // Orders 엔티티로 변환
        Orders order = new Orders();
        order.setOrderId(ordersDTO.getOrderId());
        order.setShop(shop);
        order.setMember(member);
        order.setDelivery_state(0);  // 초기 배송 상태 설정
        order.setQuantity(ordersDTO.getQuantity());  // 상품 수량 저장
        order.setTotalPrice(ordersDTO.getTotalPrice());

        // 주문을 저장
        log.info("Saving order to database: {}", order);
        ordersRepository.save(order);

        log.info("Order registered successfully with orderId: {}", ordersDTO.getOrderId());
    }

    @Override
    public void updateDeliveryState(int deliveryStatus, String orderId, int shopId) {
        Orders order = ordersRepository.findByOrderIdAndShop_ShopId(orderId, shopId)
                .orElseThrow(() -> new RuntimeException("주문을 찾을 수 없습니다: " + orderId + ", 상품 ID: " + shopId));
        order.setDelivery_state(deliveryStatus);
        ordersRepository.save(order);
    }

    @Override
    public List<OrdersDetailDTO> findOne(int orderId) {
        List<OrdersDetailDTO> ordersDetailList = ordersRepository.findAllByOrderId(orderId)
                .stream().map(orders -> OrdersDetailDTO.builder()
                        .id(orders.getId())
                        .regDate(orders.getRegDate())
                        .orderId(orders.getOrderId())
                        .shopId(orders.getShop().getShopId())
                        .shopName(orders.getShop().getName())
                        .price(orders.getShop().getPrice())
                        .quantity(orders.getQuantity())
                        .memberId(orders.getMember().getMemberId())
                        .name(orders.getMember().getName())
                        .phone(orders.getMember().getPhone())
                        .address(orders.getMember().getAddress())
                        .deliveryState(orders.getDelivery_state())
                        .deliveryPrice(3000)
                        .totalPrice(orders.getTotalPrice())
                        .build())
                .collect(Collectors.toList());
        return ordersDetailList;
    }

    @Override
    public OrdersDTO findOneByOrderId(Integer memberId) {
        return null;
    }

//    @Override
//    public List<OrdersDTO> findAll() {
////        List<OrdersDTO> ordersDTOList = entityListToDtoList(ordersRepository.findAll());
//        List<Orders> result = ordersRepository.findAll();
//        log.info("Orders found: {}", result);
//
//        List<OrdersDTO> ordersDTOList = entityListToDtoList(result);
//
//        return ordersDTOList;
//    }


    @Override
    public List<OrdersDTO> findAll() {
        List<Orders> result = ordersRepository.findAll();
//        log.info("Orders found1: {}", result);

        // 엔티티 리스트를 DTO 리스트로 변환
        List<OrdersDTO> ordersDTOList = result.stream()
                .map(order -> OrdersDTO.builder()
                        .id(order.getId())
                        .orderId(order.getOrderId())
                        .quantity(order.getQuantity())
                        .deliveryState(order.getDelivery_state())
                        .phone(order.getMember().getPhone())
                        .address(order.getMember().getAddress())
                        .totalPrice(order.getTotalPrice())
                        .shopId(order.getShop().getShopId())
                        .shopPrice(order.getShop().getPrice())
                        .shopName(order.getShop().getName())
                        .name(order.getMember().getName())
                        .memberId(order.getMember().getMemberId())
                        .build())
                .collect(Collectors.toList());

//        log.info("Orders found2: {}", ordersDTOList);

        log.info(ordersDTOList);
        return ordersDTOList;
    }

    @Override
    public int cancel(int orderId) {
        ordersRepository.findAllByOrderId(orderId)
                .stream()
                .peek(order -> order.setDelivery_state(4))
                .forEach(ordersRepository::save);
        return 0;
    }

    // 주문을 orderId로 조회하는 메서드 추가 (orderId는 String)
    public OrdersDTO findOneByOrderId(String orderId) {
        Orders orders = ordersRepository.findByOrderId(orderId)
                .orElseThrow(() -> new RuntimeException("Order not found with orderId: " + orderId));
        return entityToDto(orders);
    }
}
