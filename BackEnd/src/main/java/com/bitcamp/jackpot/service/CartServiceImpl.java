package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Cart;
import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.CartDTO;
import com.bitcamp.jackpot.jwt.CustomUserDetails;
import com.bitcamp.jackpot.repository.CartRepository;
import com.bitcamp.jackpot.repository.MemberRepository;
import com.bitcamp.jackpot.repository.ShopRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class CartServiceImpl implements CartService {
    private final CartRepository cartRepository;
    private final MemberRepository memberRepository;
    private final ModelMapper modelMapper; // ModelMapper 주입
    private final ShopRepository shopRepository;

    // 로그인된 사용자 정보를 가져오는 메서드
    private CustomUserDetails getUserDetails() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (CustomUserDetails) auth.getPrincipal();
    }

    // 로그인된 사용자 이메일을 가져오는 메서드
    private String getUserEmailFromToken() {
        CustomUserDetails userDetails = getUserDetails();
        return userDetails.getUsername(); // CustomUserDetails의 getUsername 메서드를 사용해 이메일 가져오기
    }

    @Override
    public void register(CartDTO cartDTO) {
        log.info("장바구니 등록 요청: {}", cartDTO);
        String email = getUserEmailFromToken();
        Member member = memberRepository.findByEmail(email).orElseThrow(() ->
                new IllegalArgumentException("유효한 사용자를 찾을 수 없습니다."));

        Shop shop = shopRepository.findById(cartDTO.getShopId()).orElseThrow();

        cartRepository.save(Cart.builder()
                .quantity(cartDTO.getQuantity())
                .shop(shop)
                .member(member)
                .build());
    }

    @Override
    public void edit(CartDTO cartDTO) {
        log.info("장바구니 항목 수정 요청: {}", cartDTO);

        String email = getUserEmailFromToken();
        Member member = memberRepository.findByEmail(email).orElseThrow(() ->
                new IllegalArgumentException("유효한 사용자를 찾을 수 없습니다."));

        Cart cart = dtoToEntity(cartDTO, member);
        cartRepository.save(cart);
    }

    @Override
    public void remove(Integer cartId) {
        log.info("장바구니 항목 제거 요청: {}", cartId);
        cartRepository.deleteById(cartId);
    }

    @Override
    public List<CartDTO> findAll() {
        String email = getUserEmailFromToken();
        List<Cart> carts = cartRepository.findAllByMemberEmail(email);

        return carts.stream().map(cart -> CartDTO.builder()
                .cartId(cart.getCartId())
                .shopId(cart.getShop().getShopId())
                .shopName(cart.getShop().getName())
                .shopPrice(cart.getShop().getPrice())
                .quantity(cart.getQuantity())
                .memberId(cart.getMember().getMemberId())
                .build()).collect(Collectors.toList());
    }

    public boolean updateCartQuantity(Integer cartId, int quantity) {
        // cartId로 장바구니 항목 찾기
        Cart cart = cartRepository.findById(cartId)
                .orElseThrow(() -> new RuntimeException("해당 장바구니 항목을 찾을 수 없습니다."));

        // 수량 업데이트
        cart.setQuantity(quantity);

        // 변경사항 저장
        cartRepository.save(cart);

        return true;
    }
}
