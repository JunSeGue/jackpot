package com.bitcamp.jackpot.config;

import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RootConfig {

    @Bean
    public ModelMapper modelMapper() {
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration()
                .setFieldMatchingEnabled(true)
                .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE)
                .setMatchingStrategy(MatchingStrategies.STRICT);
        // 매칭스트래터지스.LOOSE에서 STRICT로 고침. (리플라이DTO와 리플라이 매핑오류 해결을 위해.)
        // 매칭스트래터지스는 루즈, 스탠다드, 스트릭트 세가지가 있음.
        return modelMapper;
    }
}