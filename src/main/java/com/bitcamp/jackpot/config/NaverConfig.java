package com.bitcamp.jackpot.config;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:/naver.properties")
@ConfigurationProperties(prefix = "ncp")
@Getter
@Setter
@ToString
public class NaverConfig {
    private String accessKey;
    private String secretKey;
    private String regionName;
    private String endPoint;
}
