package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.dto.OrdersDTO;
import com.bitcamp.jackpot.dto.OrdersDetailDTO;
import com.bitcamp.jackpot.service.OrdersService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/order")
@Log4j2
@RequiredArgsConstructor
//@CrossOrigin("*")
public class OrderController {

    private final OrdersService ordersService;

    @PostMapping("/register")
    public void register(@RequestBody OrdersDTO ordersDTO) {
        log.info("Order ID from Frontend: " + ordersDTO.getOrderId());

        log.info(ordersDTO);
        ordersService.register(ordersDTO);
    }

    @PostMapping("/edit")
    public void edit(@RequestBody OrdersDTO ordersDTO) {
        log.info("Received OrdersDTO: {}", ordersDTO);

        // 주문 상태 업데이트 로직
        ordersService.updateDeliveryState(ordersDTO.getDeliveryState(), ordersDTO.getOrderId(), ordersDTO.getShopId());
    }

    @GetMapping("/findAll")
    public List<OrdersDTO> findAll() {
        return ordersService.findAll();
    }

    @GetMapping("/findOne")
    public List<OrdersDetailDTO> findOne(@RequestParam Integer orderId) {
        return ordersService.findOne(orderId);
    }

    @PostMapping("/cancel")
    public int cancel(@RequestParam Integer orderId) {
        return ordersService.cancel(orderId);
    }

}
