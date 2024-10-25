package com.bitcamp.jackpot.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshDTO {

    private int id;

    private String username;
    private String refresh;
    private String expiration;
}
