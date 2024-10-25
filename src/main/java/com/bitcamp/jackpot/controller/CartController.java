package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.domain.Cart;
import com.bitcamp.jackpot.dto.CartDTO;
import com.bitcamp.jackpot.repository.MemberRepository;
import com.bitcamp.jackpot.repository.ShopRepository;
import com.bitcamp.jackpot.service.CartService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/cart")
@Log4j2
@RequiredArgsConstructor
//@CrossOrigin("*")
public class CartController {

    private final CartService cartService;

    @PostMapping("/register")
    public void register(@RequestBody CartDTO cartDTO) {
        log.info(cartDTO);
        cartService.register(cartDTO);
    }

    @PostMapping("/edit")
    public void edit(@RequestBody CartDTO cartDTO) {
        log.info(cartDTO);
        cartService.edit(cartDTO);
    }

    @GetMapping("/findAll")
    public List<CartDTO> findAll() {
        List<CartDTO> result= cartService.findAll();
        log.info(result);
        return result;
    }

//    @GetMapping("/findone")
//    public CartDTO findOne(@RequestParam Integer cartId) {
//        log.info(cartId);
//        CartDTO cartDTO = cartService.findOne(cartId);
//        log.info(cartDTO);
//        return cartDTO;
//    }

    @DeleteMapping("/remove")
    public void remove(@RequestParam Integer cartId) {
        log.info(cartId);
        cartService.remove(cartId);
    }

    @PostMapping("/update")
    public ResponseEntity<String> updateCartQuantity(
            @RequestParam Integer cartId,
            @RequestParam int quantity) {

        try {
            boolean isUpdated = cartService.updateCartQuantity(cartId, quantity);

            if (isUpdated) {
                return ResponseEntity.ok("\"status\":200, 장바구니 수량이 업데이트되었습니다.");
            } else {
                return ResponseEntity.badRequest().body("\"status\":400,수량 업데이트에 실패했습니다.");
            }

        } catch (Exception e) {
            // 예외 처리
            return ResponseEntity.status(500).body("\"status\": 500, 서버에서 오류가 발생했습니다.");
        }
    }
}
