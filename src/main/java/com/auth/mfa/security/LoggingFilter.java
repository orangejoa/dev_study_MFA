package com.auth.mfa.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

public class LoggingFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // 초기화 로직 필요시 구현
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String requestURL = httpRequest.getRequestURL().toString();
        if (requestURL.contains(";")) {
            System.out.println("세미콜론 포함되서 거절된 URL " + requestURL);
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // 정리 로직 필요시 구현
    }
}
