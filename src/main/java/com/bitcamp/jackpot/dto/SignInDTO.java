package com.bitcamp.jackpot.dto;

import lombok.Data;
import lombok.Getter;

@Getter
@Data
public class SignInDTO {
    private String email;
    private String pwd;
}
