package com.bitcamp.jackpot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class JackpotApplication {

    public static void main(String[] args) {
        SpringApplication.run(JackpotApplication.class, args);
    }
}
