package com.bitcamp.jackpot.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.*;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class BoardDTO {

//    @NotNull
    // 서비스단에서 +1 해줄거라 낫널 애너테이션 주석처리.
    private Integer boardId;

//    @NotNull
    private Integer memberId;

//    @NotEmpty
    private String title;

//    @NotEmpty
    private String content;

    @JsonFormat(pattern="yyyy-MM-dd HH:mm:ss")
    private LocalDateTime regDate;

//    @NotNull
    private Integer type;

}