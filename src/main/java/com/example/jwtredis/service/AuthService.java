package com.example.jwtredis.service;

import com.example.jwtredis.dto.LoginRequest;
import com.example.jwtredis.dto.RefreshTokenRequest;
import com.example.jwtredis.dto.TokenResponse;
import com.example.jwtredis.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final ReactiveAuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenCacheService tokenCacheService;
    private final TokenBlacklistService blacklistService;

    public Mono<TokenResponse> login(LoginRequest request) {
        return authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        request.getUsername(), request.getPassword()))
                .flatMap(this::generateAndCacheTokens)
                .doOnSuccess(r -> log.info("Login exitoso: {}", r.getUsername()))
                .doOnError(e -> log.error("Login fallido para {}: {}", request.getUsername(), e.getMessage()));
    }

    public Mono<TokenResponse> refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        if (!jwtTokenProvider.validateToken(refreshToken) ||
                !jwtTokenProvider.isRefreshToken(refreshToken)) {
            return Mono.error(new IllegalArgumentException("Refresh token invalido o expirado"));
        }

        String username = jwtTokenProvider.extractUsername(refreshToken);

        return tokenCacheService.isRefreshTokenValid(username, refreshToken)
                .flatMap(isValid -> {
                    if (!isValid) {
                        log.warn("Refresh token no coincide con el almacenado en Redis para: {}", username);
                        return Mono.<TokenResponse>error(
                                new IllegalArgumentException("Refresh token invalido"));
                    }
                    return tokenCacheService.deleteRefreshToken(username)
                            .then(generateTokensForUser(username,
                                    jwtTokenProvider.extractRoles(refreshToken)));
                })
                .doOnSuccess(r -> log.info("Tokens renovados para: {}", username));
    }

    public Mono<Void> logout(String accessToken) {
        if (!jwtTokenProvider.validateToken(accessToken)) {
            return Mono.error(new IllegalArgumentException("Token invalido"));
        }

        String username = jwtTokenProvider.extractUsername(accessToken);
        log.info("Logout para usuario: {}", username);

        return Mono.when(
                blacklistService.blacklistToken(accessToken),
                tokenCacheService.deleteRefreshToken(username)
        );
    }

    private Mono<TokenResponse> generateAndCacheTokens(Authentication authentication) {
        List<String> roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        return generateTokensForUser(authentication.getName(), roles);
    }

    private Mono<TokenResponse> generateTokensForUser(String username, List<String> roles) {
        String accessToken = jwtTokenProvider.generateAccessToken(username, roles);
        String refreshToken = jwtTokenProvider.generateRefreshToken(username);

        return tokenCacheService.saveRefreshToken(username, refreshToken)
                .then(tokenCacheService.cacheAccessToken(username, accessToken))
                .thenReturn(TokenResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .tokenType("Bearer")
                        .accessExpiresIn(jwtTokenProvider.getAccessExpirationInSeconds())
                        .refreshExpiresIn(jwtTokenProvider.getRefreshExpirationInSeconds())
                        .username(username)
                        .roles(roles)
                        .build());
    }
}
