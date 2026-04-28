package com.example.jwtredis.service;
import com.example.jwtredis.dto.*;
import com.example.jwtredis.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.*;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.util.List;
@Slf4j @Service @RequiredArgsConstructor
public class AuthService {
    private final ReactiveAuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenCacheService tokenCacheService;
    private final TokenBlacklistService blacklistService;
    public Mono<TokenResponse> login(LoginRequest request) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()))
                .flatMap(auth -> {
                    List<String> roles = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
                    return generateTokensForUser(auth.getName(), roles);
                }).doOnSuccess(r -> log.info("Login exitoso: {}", r.getUsername()));
    }
    public Mono<TokenResponse> refreshToken(RefreshTokenRequest request) {
        String rt = request.getRefreshToken();
        if (!jwtTokenProvider.validateToken(rt) || !jwtTokenProvider.isRefreshToken(rt))
            return Mono.error(new IllegalArgumentException("Refresh token invalido o expirado"));
        String username = jwtTokenProvider.extractUsername(rt);
        return tokenCacheService.isRefreshTokenValid(username, rt)
                .flatMap(valid -> {
                    if (!valid) return Mono.<TokenResponse>error(new IllegalArgumentException("Refresh token invalido"));
                    return tokenCacheService.deleteRefreshToken(username)
                            .then(generateTokensForUser(username, jwtTokenProvider.extractRoles(rt)));
                });
    }
    public Mono<Void> logout(String accessToken) {
        if (!jwtTokenProvider.validateToken(accessToken)) return Mono.error(new IllegalArgumentException("Token invalido"));
        String username = jwtTokenProvider.extractUsername(accessToken);
        return Mono.when(blacklistService.blacklistToken(accessToken), tokenCacheService.deleteRefreshToken(username));
    }
    private Mono<TokenResponse> generateTokensForUser(String username, List<String> roles) {
        String at = jwtTokenProvider.generateAccessToken(username, roles);
        String rt = jwtTokenProvider.generateRefreshToken(username);
        return tokenCacheService.saveRefreshToken(username, rt)
                .then(tokenCacheService.cacheAccessToken(username, at))
                .thenReturn(TokenResponse.builder().accessToken(at).refreshToken(rt).tokenType("Bearer")
                        .accessExpiresIn(jwtTokenProvider.getAccessExpirationInSeconds())
                        .refreshExpiresIn(jwtTokenProvider.getRefreshExpirationInSeconds())
                        .username(username).roles(roles).build());
    }
}