package com.auth.mfa.config;

import com.auth.mfa.security.LoggingFilter;
import com.auth.mfa.service.CustomOAuth2UserService;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService) {
        this.customOAuth2UserService = customOAuth2UserService;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf((csrf) -> csrf.disable())
                //formLogin() URL에 자동으로 로그인 페이지 생성
                .formLogin((login) -> login.disable())
                //Http Basic 인증
                .httpBasic((basic) -> basic.disable())
                .oauth2Login((oauth2) -> oauth2.userInfoEndpoint(userInfoEndpointConfig ->
                        userInfoEndpointConfig.userService(customOAuth2UserService)))
                .authorizeHttpRequests((auth) ->
                        auth.requestMatchers("/").permitAll().anyRequest().authenticated())
                .addFilterBefore(new LoggingFilter(), SecurityContextPersistenceFilter.class);
        return http.build();
    }

}
