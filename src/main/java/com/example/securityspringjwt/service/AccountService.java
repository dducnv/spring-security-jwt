package com.example.securityspringjwt.service;

import com.example.securityspringjwt.entity.Account;
import com.example.securityspringjwt.entity.dto.AccountLoginDto;
import com.example.securityspringjwt.entity.dto.AccountRegisterDto;
import com.example.securityspringjwt.entity.dto.Credential;
import com.example.securityspringjwt.repository.AccountRepository;
import com.example.securityspringjwt.utils.JwtUtil;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
@Service
@AllArgsConstructor
public class AccountService implements UserDetailsService {
    @Autowired
    final AccountRepository accountRepository;
    @Autowired
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    public AccountRegisterDto register(AccountRegisterDto accountRegisterDto) {
        Optional<Account> account = accountRepository.findByEmail(accountRegisterDto.getEmail());
        if (account.isPresent()) {
            return null;
        }
        Account newAccount = Account.builder()
                .name(accountRegisterDto.getName())
                .email(accountRegisterDto.getEmail())
                .password(bCryptPasswordEncoder.encode(accountRegisterDto.getPassword()))
                .role(accountRegisterDto.getRole())
                .build();
                accountRepository.save(newAccount);
                accountRegisterDto.setEmail(newAccount.getEmail());
                return accountRegisterDto;

    }

    public Credential login(AccountLoginDto accountLoginDto) {
        Optional<Account>  optionalAccount = accountRepository.findByEmail(accountLoginDto.getEmail());
        if (!optionalAccount.isPresent()) {
            return null;
        }
        Account account = optionalAccount.get();
        if (bCryptPasswordEncoder.matches(accountLoginDto.getPassword(), optionalAccount.get().getPassword())) {
            int expiredTime = 7;
            String assessToken = JwtUtil.generateTokenByAccount(account, expiredTime * 24 * 60 * 60 * 1000);
            String refreshToken = JwtUtil.generateTokenByAccount(account, 14 * 24 * 60 * 60 * 1000);
            return Credential.builder()
                    .accessToken(assessToken)
                    .refreshToken(refreshToken)
                    .expiresIn(expiredTime)
                    .scope("basic_info")
                    .build();
        }else {
            throw new RuntimeException("password is wrong");
        }

    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<Account> optionalAccount = accountRepository.findByEmail(email);
        if(!optionalAccount.isPresent()){
          throw new UsernameNotFoundException("User not found");
        }
        Account account = optionalAccount.get();
        List<GrantedAuthority> authorities = new ArrayList<>();
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority(account.getRole());
        authorities.add(authority);
        return new User(account.getEmail(),account.getPassword(),authorities);
    }
}
