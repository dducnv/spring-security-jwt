package com.example.securityspringjwt.entity.dto;

import com.example.securityspringjwt.entity.Account;
import com.example.securityspringjwt.repository.AccountRepository;
import lombok.*;

import java.nio.file.FileStore;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountRegisterDto {
    private String name;
    private String email;
    private String password;
    private String confirmPassword;
    private String role;
}
