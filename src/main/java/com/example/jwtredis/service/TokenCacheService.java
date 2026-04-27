package com.example.jwtredis.service;

import com.example.jwtredis.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenCacheService {

    private final ReactiveStringRedisTemplate redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;

    @Value("${app.redis.prefix.refresh-token}")
    private String refreshPrefix;

    @Value("${app.redis.prefix.user-tokens}")
    private String userTokensPrefix;

    public Mono<Boolean> saveRefreshToken(String username, String refreshToken) {
        long ttl = jwtTokenProvider.getRefreshExpirationInSeconds();
        String key = refreshPrefix + username;
        return redisTemplate.opsForValue()
                .set(key, refreshToken, Duration.ofSeconds(ttl))
                .doOnSuccess(r -> log.debug("Refresh token guardado para usuario: {}", username));
    }

    public Mono<String> getRefreshToken(String username) {
        return redisTemplate.opsForValue()
                .get(refreshPrefix + username)
                .doOnNext(t -> log.debug("Refresh token recuperado para: {}", username));
    }

    public Mono<Boolean> isRefreshTokenValid(String username, String refreshToken) {
        return getRefreshToken(username)
                .map(stored -> stored.equals(refreshToken))
                .defaultIfEmpty(false);
    }

    public Mono<Boolean> deleteRefreshToken(String username) {
        return redisTemplate.delete(refreshPrefix + username)
                .map(count -> count > 0)
                .doOnSuccess(r -> log.info("Refresh token eliminado para: {}", username));
    }

    public Mono<Boolean> cacheAccessToken(String username, String accessToken) {
        long ttl = jwtTokenProvider.getAccessExpirationInSeconds();
        return redisTemplate.opsForValue()
                .set(userTokensPrefix + username, accessToken, Duration.ofSeconds(ttl));
    }

    public Mono<String> getCachedAccessToken(String username) {
        return redisTemplate.opsForValue().get(userTokensPrefix + username);
    }
}
