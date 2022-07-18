package com.example.securityspringjwt.api;

import com.example.securityspringjwt.entity.dto.AccountLoginDto;
import com.example.securityspringjwt.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/_v1/auth")
@RequiredArgsConstructor
public class AuthController {
    final AccountService accountService;

    @RequestMapping(method = RequestMethod.POST, value = "/login")
    public ResponseEntity<?> login(@RequestBody AccountLoginDto accountLoginDto) {
         return ResponseEntity.ok().body(accountService.login(accountLoginDto));
    }
}
