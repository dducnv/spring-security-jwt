package com.example.securityspringjwt.security.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
@Configuration
@AllArgsConstructor
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/api/_v*/auth/**")
                .permitAll();

        http
                .authorizeRequests()
                .antMatchers("/api/_v*/user/**")
                .hasAnyAuthority("ADMIN", "USER");

        http
                .authorizeRequests()
                .antMatchers("/api/_v*/admin/**")
                .hasAuthority("ADMIN");

    }
}
