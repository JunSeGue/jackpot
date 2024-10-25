package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.dto.OrdersDTO;
import com.bitcamp.jackpot.dto.PageRequestDTO;
import com.bitcamp.jackpot.dto.PageResponseDTO;
import com.bitcamp.jackpot.dto.ShopDTO;

import java.util.List;

public interface ShopService {

    void register(ShopDTO shopDTO);

    void edit(int shopId, ShopDTO shopDTO);

    void remove(int shopId);

    void addBuyCount(int shopId, int buyCount);

    ShopDTO findOne(int shopId);

    PageResponseDTO<ShopDTO> findList(PageRequestDTO pageRequestDTO);

    PageResponseDTO<ShopDTO> findListAdmin(PageRequestDTO pageRequestDTO);

    PageResponseDTO<ShopDTO> search(String name, PageRequestDTO pageRequestDTO);

    PageResponseDTO<ShopDTO> findByCategory(int category, PageRequestDTO pageRequestDTO);

    List<OrdersDTO> findOrderList(PageRequestDTO pageRequestDTO);
}
