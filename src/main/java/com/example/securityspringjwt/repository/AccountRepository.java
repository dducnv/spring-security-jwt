package com.example.securityspringjwt.repository;

import com.example.securityspringjwt.entity.Account;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByEmail(String email);

    Account findByEmailAndPassword(String email, String password);
}
