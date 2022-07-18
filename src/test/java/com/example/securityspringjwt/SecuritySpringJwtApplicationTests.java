package com.example.securityspringjwt;

import com.example.securityspringjwt.entity.dto.AccountRegisterDto;
import com.example.securityspringjwt.service.AccountService;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = SecuritySpringJwtApplication.class)
class SecuritySpringJwtApplicationTests {

    @Autowired
    AccountService accountService;
    @Test
    void register() {
        AccountRegisterDto accountRegisterDto = AccountRegisterDto.builder()
                .name("test")
                .email("test@example")
                .password("test")
                .role("USER")
                .build();
        accountService.register(accountRegisterDto);
    }

    @Test
    public void testToken() {

    }

}
