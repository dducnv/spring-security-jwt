package com.example.securityspringjwt.entity.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AccountLoginDto {
    private String email;
    private String password;
}
