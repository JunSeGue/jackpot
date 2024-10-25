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
public class ReplyDTO {

//    @NotNull
    private Integer replyId;

//    @NotNull
    private Integer memberId;

    @NotNull
    private Integer boardId;

    @NotEmpty
    private String content;

    @JsonFormat(pattern="yyyy-MM-dd HH:mm:ss")
    private LocalDateTime regDate;
}