package com.auth.mfa.config;

import com.auth.mfa.domain.member.Role;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security Config
 */
@Configuration
//모든 요청 URL이 Spring Security의 제어를 받는다.
//@EnableWebSecurity 사용 시, 내부적으로 SpringSecurityFilterChain이 동작하여 URL 필터가 적용
@EnableWebSecurity
public class SecurityConfig {
    /**
     * Filter chain security filter chain.
     *
     * @param http the http
     * @return the security filter chain
     * @throws Exception the exception
     */
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf((csrfConfig) -> csrfConfig.disable()
                )
                .headers((headerConfig) -> headerConfig.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable())
                )
                .authorizeRequests((authorizeRequests) ->
                        authorizeRequests
                                //h2-console을 사용하기 위한 설정
                                .requestMatchers(PathRequest.toH2Console()).permitAll()
                                //메인화면과 로그인 및 회원가입 화면은 권한에 상관없이 접근할 수 있어야 하므로 permitAll()로 모든 접근 허용
                                .requestMatchers("/","/login/**").permitAll()
                                //posts 관련 요청 : 로그인 인증을 하여 USER권한을 획득한 사용자만 접근 가능
                                .requestMatchers("/posts/**","/api/v1/posts/**").hasRole(Role.USER.name())
                                //ADMIN 관련 요청은 ADMIN 권한이 있어야 접근 가능
                                .requestMatchers("/admins/**", "/api/v1/admins/**").hasRole(Role.ADMIN.name())
                                .anyRequest().authenticated()
                );
        return http.build();
    }

}
