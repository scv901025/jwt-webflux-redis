package com.example.jwtredis.filter;
import com.example.jwtredis.security.CustomUserDetailsService;
import com.example.jwtredis.security.JwtTokenProvider;
import com.example.jwtredis.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.*;
import reactor.core.publisher.Mono;
@Slf4j @Component @RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {
    private static final String BEARER_PREFIX = "Bearer ";
    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService blacklistService;
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);
        if (token == null || !jwtTokenProvider.validateToken(token) || jwtTokenProvider.isRefreshToken(token))
            return chain.filter(exchange);
        String username = jwtTokenProvider.extractUsername(token);
        return blacklistService.isNotBlacklisted(token)
                .flatMap(notBlacklisted -> {
                    if (!notBlacklisted) return chain.filter(exchange);
                    return userDetailsService.findByUsername(username)
                            .map(u -> new UsernamePasswordAuthenticationToken(u, null, u.getAuthorities()))
                            .flatMap(auth -> chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)))
                            .switchIfEmpty(chain.filter(exchange));
                });
    }
    private String extractToken(ServerWebExchange exchange) {
        String h = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return (StringUtils.hasText(h) && h.startsWith(BEARER_PREFIX)) ? h.substring(BEARER_PREFIX.length()) : null;
    }
}