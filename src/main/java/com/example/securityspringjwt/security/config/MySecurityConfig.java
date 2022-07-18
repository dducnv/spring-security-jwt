package com.example.securityspringjwt.security.config;

import com.example.securityspringjwt.middleware.AuthorizationMiddleware;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@AllArgsConstructor
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        AuthorizationMiddleware authorizationMiddleware = new AuthorizationMiddleware(authenticationManager());
        authorizationMiddleware.setFilterProcessesUrl("/api/_v1/auth/login");
        http.cors().and().csrf().disable();
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

        http
                .addFilter(authorizationMiddleware);
    }
}
