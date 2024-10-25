package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.dto.AuctionDTO;
import com.bitcamp.jackpot.dto.BiddingDTO;
import com.bitcamp.jackpot.service.BiddingService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@Log4j2
@RequiredArgsConstructor
@RequestMapping("/bid")
public class BidController {
    private final BiddingService biddingService;
    private final String nodeWebSocketUrl = "http://10.0.7.6:3001";

    private void sendToNodeWebSocket(BiddingDTO biddingDTO, String endpoint) {
        String fullEndpoint = nodeWebSocketUrl + endpoint;
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.postForObject(fullEndpoint, biddingDTO, String.class);  // Node.js로 경매 데이터를 전송
    }

    @GetMapping("/highest")
    public int findHighestBidPrice() {
        return biddingService.findHighestBidPrice();
    }

    @PostMapping("/register")
    public void register(@RequestBody BiddingDTO biddingDTO) {
        biddingService.register(biddingDTO);
        sendToNodeWebSocket(biddingDTO, "/send-bid");
    }

    @GetMapping("/before")
    public BiddingDTO findBeforBidding(int biddingId) {
        BiddingDTO biddingDTO = biddingService.findBeforeBidding(biddingId);
        return biddingDTO;
    }

    @DeleteMapping("/remove")
    public void remove(@RequestParam("auctionId") int auctionId, @RequestParam("memberID") int memberID) {
        biddingService.remove(auctionId, memberID);
        if (biddingService.isAuctionEnded(auctionId)) {
            log.info("경매는 이미 종료되었습니다: " + auctionId);
            return;  // 이미 종료된 경매에 대해서는 Node.js로 추가 요청을 보내지 않음
        }

        BiddingDTO biddingDTO = new BiddingDTO();
        biddingDTO.setAuctionId(auctionId);
        biddingDTO.setMemberID(memberID);
        biddingDTO.setAuctionStatus(2);

        // Node.js 서버에 종료된 경매 데이터를 전송 (Node.js WebSocket 서버로 요청)
        sendToNodeWebSocket(biddingDTO, "/end-auction");
    }

    @GetMapping("/end")
    public void endAuction() {
        BiddingDTO lastBiddingDTO = biddingService.findLastBidder();
        log.info(lastBiddingDTO);
        sendToNodeWebSocket(lastBiddingDTO, "/last-bidder");
    }
}
