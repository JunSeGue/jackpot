package com.bitcamp.jackpot.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class VerificationCodeDTO {

    @NotBlank(message = "Code is required")
    @Size(min = 6, max = 6, message = "Code must be exactly 6 characters")
    private String code;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

}