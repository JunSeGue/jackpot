package com.bitcamp.jackpot.dto;

import lombok.*;
import javax.validation.constraints.*;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MemberDTO {


    private int memberID;

    @NotEmpty(message ="이름은 필수 입니다.")
    private String name;

    @Email
    @NotEmpty(message = "이메일은 필수 입력 항목입니다.")
    private String email;

    private String phone;

    @Size(min = 8, message = "비밀번호는 8자 이상이어야 합니다.")
    @NotEmpty(message = "비밀번호는 필수 입력 항목입니다.")
    private String pwd;

    @Size(max = 30, message = "닉네임은 최대 30자까지 입력 가능합니다.")
    @NotEmpty(message = "닉네임은 필수 입력 항목입니다.")
    private String nickName;

    private String address;

    @Builder.Default
    private int grade = 1; // 기본값을 1로 설정



}
