package com.example.securityspringjwt.middleware;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.securityspringjwt.entity.dto.AccountLoginDto;
import com.example.securityspringjwt.entity.dto.Credential;
import com.example.securityspringjwt.utils.JwtUtil;
import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class AuthorizationMiddleware extends UsernamePasswordAuthenticationFilter {

    final AuthenticationManager authenticationManager;
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        try {
//            String fullToken = request.getHeader("Authorization");
//            String token = fullToken.replace("Bearer ", "").trim();
//            DecodedJWT  decodedJWT = JwtUtil.getDecodedJwt(token);
//            if (decodedJWT == null) {
//                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                return;
//            }
//            String accountId = decodedJWT.getSubject();
//            String email = decodedJWT.getClaim("email").asString();
//            String role = decodedJWT.getClaim("role").asString();
//            Collection<GrantedAuthority> authorities = new ArrayList<>();
//            authorities.add(new SimpleGrantedAuthority(role));
//            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(accountId, null, authorities);
//            SecurityContextHolder.getContext().setAuthentication(authentication);
//        }catch (Exception e){
//            e.printStackTrace();
//        }
//        filterChain.doFilter(request, response);
//    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            String body = request.getReader().lines().collect(Collectors.joining());
            Gson gson = new Gson();
            AccountLoginDto accountLoginDto = gson.fromJson(body, AccountLoginDto.class);
            Credential credential = new Gson().fromJson(body, Credential.class);
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(accountLoginDto.getEmail(),accountLoginDto.getPassword());
            return authenticationManager.authenticate(authRequest);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User)authResult.getPrincipal();
        String accessToken = JwtUtil.generateToken(user.getUsername(),
                user.getAuthorities().iterator().next().getAuthority(),
                request.getRequestURL().toString(),
                JwtUtil.ONE_DAY * 7);
        String refreshToken = JwtUtil.generateToken(user.getUsername(),
                user.getAuthorities().iterator().next().getAuthority(),
                request.getRequestURL().toString(),
                JwtUtil.ONE_DAY * 14);
        Credential credential = Credential.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(JwtUtil.ONE_DAY * 7)
                .tokenType("Bearer")
                .scope("basic_info")
                .build();
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Gson gson = new Gson();
        response.getWriter().write(gson.toJson(credential));
    }
    @Override
    protected  void  unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        HashMap<String, String> errors = new HashMap<>();
        errors.put("message", "Authentication failed");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Gson gson = new Gson();
        response.getWriter().write(gson.toJson(errors));
    }
}
