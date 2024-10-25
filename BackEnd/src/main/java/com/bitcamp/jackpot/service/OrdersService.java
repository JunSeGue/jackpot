package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Orders;
import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.OrdersDTO;
import com.bitcamp.jackpot.dto.OrdersDetailDTO;

import java.util.List;
import java.util.stream.Collectors;

public interface OrdersService {

    void register(OrdersDTO ordersDTO);

    void updateDeliveryState(int deliveryStatus, String orderId, int shopId);

    List<OrdersDetailDTO> findOne(int orderId);

    OrdersDTO findOneByOrderId(Integer memberId);

    List<OrdersDTO> findAll();

    int cancel(int orderId);

    // DTO -> Entity 변환 메서드 (orderId는 String으로, id는 DB에서 자동 생성)
    default Orders dtoToEntity(OrdersDTO ordersDTO) {
        Member member = Member.builder().name(ordersDTO.getName()).build();

        // shopId만 사용하여 Shop을 조회하고 매핑
        Shop shop = Shop.builder()
                .shopId(ordersDTO.getShopId())  // shopId로 Shop 엔티티 생성
                .build();

        return Orders.builder()
                .orderId(ordersDTO.getOrderId())  // DTO에서 엔티티로 매핑 확인
                .delivery_state(ordersDTO.getDeliveryState())  // 배송 상태
                .member(member)  // Member 엔티티
                .shop(shop)  // Shop 엔티티
                .quantity(ordersDTO.getQuantity())  // 상품 수량 매핑
                .totalPrice(ordersDTO.getTotalPrice())
                .build();
    }

    // Entity -> DTO 변환 메서드 (orderId는 String으로, id는 DB에서 자동 생성된 값)
    default OrdersDTO entityToDto(Orders orders) {
        return OrdersDTO.builder()
                .orderId(orders.getOrderId())
                .deliveryState(orders.getDelivery_state())
                .name(orders.getMember().getName())
                .phone(orders.getMember().getPhone())
                .address(orders.getMember().getAddress())
                .shopId(orders.getShop().getShopId())  // Shop의 ID를 DTO에 매핑
                .quantity(orders.getQuantity())  // 상품 갯수 매핑
                .totalPrice(orders.getTotalPrice())
                .build();
    }

    // Entity 리스트 -> DTO 리스트 변환 메서드
    default List<OrdersDTO> entityListToDtoList(List<Orders> orders) {
        return orders.stream()
                .map(this::entityToDto)
                .collect(Collectors.toList());
    }
}
