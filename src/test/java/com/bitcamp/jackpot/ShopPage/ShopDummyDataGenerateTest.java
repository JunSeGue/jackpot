package com.bitcamp.jackpot.ShopPage;

import com.bitcamp.jackpot.domain.Shop;
import com.bitcamp.jackpot.dto.ShopDTO;
import com.bitcamp.jackpot.repository.ShopRepository;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Log4j2
public class ShopDummyDataGenerateTest {

    @Autowired
    private ShopRepository shopRepository;


    @Autowired
    private ModelMapper modelMapper;

//    @Test
//    void ShopDummyDataGenerateRegister() {
//
//        // 더미 데이터 생성
//        for (int i = 1; i <= 20; i++) {
//            ShopDTO shopDTO = ShopDTO.builder()
//                    .name("Test Product " + i)
//                    .detail("This is a test product detail " + i)
//                    .category(i % 5 + 1) // 카테고리 1~5로 나눠 설정
//                    .price(String.valueOf(10000 + i)) // 가격 설정 (int)
//                    .build();
//
//            // DTO를 엔티티로 변환
//            Shop shopEntity = modelMapper.map(shopDTO, Shop.class);
//
//            // 더미 데이터를 저장
//            shopRepository.save(shopEntity);
//
//            log.info("Saved Shop Entity: " + shopEntity);
//
//        }
//    }
}
