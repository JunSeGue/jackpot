package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Cart;
import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.CartDTO;

import java.util.List;
import java.util.stream.Collectors;

public interface CartService {
    void register(CartDTO cartDTO);

    void edit(CartDTO cartDTO);

    void remove(Integer cartId);

    List<CartDTO> findAll();

    public boolean updateCartQuantity(Integer cartId, int quantity);

    default Cart dtoToEntity(CartDTO cartDTO, Member member) {
        Shop shop = Shop.builder().shopId(cartDTO.getShopId()).build();
        return Cart.builder()
                .cartId(cartDTO.getCartId())
                .member(member)
                .shop(shop)
                .build();
    }

    default CartDTO entityToDto(Cart cart) {
        return CartDTO.builder()
                .cartId(cart.getCartId())
                .memberId(cart.getMember() != null ? cart.getMember().getMemberId() : null)
                .shopId(cart.getShop() != null ? cart.getShop().getShopId() : null)
                .shopName(cart.getShop() != null ? cart.getShop().getName() : null)
                .shopPrice(cart.getShop() != null ? cart.getShop().getPrice() : null)
                .build();
    }

    default List<CartDTO> entityListToDtoList(List<Cart> carts) {
        return carts.stream()
                .map(this::entityToDto)
                .collect(Collectors.toList());
    }
}
