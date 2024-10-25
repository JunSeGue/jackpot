package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.dto.*;
import com.bitcamp.jackpot.service.DogService;
import com.bitcamp.jackpot.service.ObjectStorageService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/dog")
@RequiredArgsConstructor
public class DogController {

    private final DogService dogService;

    @PostMapping("/edit")
    public ResponseEntity<Integer> edit(@RequestBody DogDTO dogDTO) {
        if (dogService.edit(dogDTO) == 0) {
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        } else {
            return ResponseEntity.status(HttpStatus.CREATED).body(dogDTO.getDogId());
        }
    }

    @PostMapping("/remove")
    public void remove(@RequestParam int dogId) {
        dogService.remove(dogId);
    }

    @GetMapping("/findOne")
    public DogResponseDTO findOne(@RequestParam int dogId) {
        return dogService.findOne(dogId);
    }

    @PostMapping("/addHeart")

    public void addHeart(@RequestBody Map<String,Integer> dogId) {
       dogService.addHeart(dogId.get("dogId"));
    }

    @PostMapping("/addFund")
    public void addFund(@RequestBody FundDTO fundDTO) {
        dogService.addFund(fundDTO);
    }

    @GetMapping("/dogList")
    public Map<String, Object> dogList(@RequestParam int page, int size, String sort) {

        Map<String, Object> response = new HashMap<>();
        DogListRequestDTO dogListRequestDTO = DogListRequestDTO.builder()
                .page(page)
                .size(size)
                .sort(sort)
                .build();

        response.put("totalDogNum", dogService.getTotalDogNum());
        response.put("dogList", dogService.dogList(dogListRequestDTO));

        return response;
    }

    // 1:1문의게시판마이페이지 게시글 목록 조회, read.
    @GetMapping("/fundListMyPage")
    public ResponseEntity<Map<String,Object>> fundListMyPage() {
        Map<String,Object> response = dogService.fundListMyPage();

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(response); // 반환 타입에 맞춰서 fundDTOList를 사용
    }
}
