package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.ReviewDTO;
import com.bitcamp.jackpot.repository.MemberRepository;
import com.bitcamp.jackpot.repository.ShopRepository;
import com.bitcamp.jackpot.service.ReviewService;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/review")
@Log4j2
@RequiredArgsConstructor
//@CrossOrigin("*")
public class ReviewController {

    private final ReviewService reviewService;

    @PostMapping("/register")
    public void register(@RequestBody ReviewDTO reviewDTO) {
        log.info(reviewDTO);
        reviewService.register(reviewDTO);
    }

    @PostMapping("/edit")
    public void edit(@RequestBody ReviewDTO reviewDTO) {
        log.info(reviewDTO);
        reviewService.edit(reviewDTO);
    }

    @GetMapping("/findall")
    public List<ReviewDTO> findAll() {
        return reviewService.findAll();
    }

    @GetMapping("/findone")
    public ReviewDTO findOne(@RequestParam Integer reviewId) {
        log.info(reviewId);
        ReviewDTO reviewDTO = reviewService.findOne(reviewId);
        log.info(reviewDTO);
        return reviewDTO;
    }

    @DeleteMapping("/remove")
    public void remove(@RequestParam Integer reviewId) {
        log.info(reviewId);
        reviewService.remove(reviewId);
    }

}
