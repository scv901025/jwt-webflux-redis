package com.example.jwtredis.filter;

import com.example.jwtredis.security.CustomUserDetailsService;
import com.example.jwtredis.security.JwtTokenProvider;
import com.example.jwtredis.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService blacklistService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);

        if (token == null || !jwtTokenProvider.validateToken(token)) {
            return chain.filter(exchange);
        }

        if (jwtTokenProvider.isRefreshToken(token)) {
            log.warn("Intento de usar refresh token como access token");
            return chain.filter(exchange);
        }

        String username = jwtTokenProvider.extractUsername(token);

        return blacklistService.isNotBlacklisted(token)
                .flatMap(notBlacklisted -> {
                    if (!notBlacklisted) {
                        log.warn("Token en blacklist para usuario: {}", username);
                        return chain.filter(exchange);
                    }
                    return userDetailsService.findByUsername(username)
                            .map(this::createAuthentication)
                            .flatMap(auth -> chain.filter(exchange)
                                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)))
                            .switchIfEmpty(chain.filter(exchange));
                });
    }

    private UsernamePasswordAuthenticationToken createAuthentication(UserDetails userDetails) {
        return new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
    }

    private String extractToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}
