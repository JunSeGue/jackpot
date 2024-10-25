package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.dto.*;
import com.bitcamp.jackpot.service.AuctionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.http.HttpRequest;


@RestController
@Log4j2
@RequiredArgsConstructor
@RequestMapping("/auction")
public class AuctionController {
    private final AuctionService auctionService;
    private final String nodeWebSocketUrl = "http://10.0.7.6:3001";

    private void sendToNodeWebSocket(AuctionDTO auctionDTO, String endpoint) {
        String fullEndpoint = nodeWebSocketUrl + endpoint;
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.postForObject(fullEndpoint, auctionDTO, String.class);  // Node.js로 경매 데이터를 전송
    }

    @PostMapping("/register/{shopId}")
    public void register(@RequestBody AuctionDTO auctionDTO, @PathVariable("shopId") int shopId) {
        AuctionDTO addAuctionDTO = auctionService.register(auctionDTO, shopId);
        sendToNodeWebSocket(addAuctionDTO, "/send-auction");
    }

    @PostMapping("/edit")
    public void editAuctionStatus(@RequestBody AuctionStatusDTO auctionStatusDTO) {
        log.info(auctionStatusDTO);
        AuctionDTO auctionDTO = auctionService.edit(auctionStatusDTO.getAuctionId(), auctionStatusDTO.getAuctionStatus());
        sendToNodeWebSocket(auctionDTO, "/send-auction");
    }

    @GetMapping("/findOne/{auctionId}")
    public AuctionDTO findOne(@PathVariable("auctionId") int auctionId) {
        return auctionService.findOne(auctionId);
    }

    //    @GetMapping("/auctionNext")
//    public AuctionDTO findNextAuction() {
//        return auctionService.findNextAuction();
//    }

    @GetMapping("/current")
    public AuctionDTO getAuction() {
        AuctionDTO currentOrUpcomingAuctionDTO = auctionService.getAuction();
        // WebSocket을 통해 Node 서버로 경매 데이터를 전송
        sendToNodeWebSocket(currentOrUpcomingAuctionDTO, "/send-auction");
        // 경매 데이터를 클라이언트에 반환
        return currentOrUpcomingAuctionDTO;
    }

    @GetMapping("/findList")
    public PageResponseDTO<AuctionDTO> findList(PageRequestDTO pageRequestDTO) {
        log.info(pageRequestDTO);
        return auctionService.findAll(pageRequestDTO);
    }
}
