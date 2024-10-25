package com.bitcamp.jackpot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.support.StandardMultipartHttpServletRequest;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DogRegistDTO {
    private int dogId;

    private String name;

    private String species;

    private int age;

    private int gender;

    private int heart;

    private String videoUrl;

    private String dogDetail;

    private LocalDateTime regDate;

    private String title;
}
