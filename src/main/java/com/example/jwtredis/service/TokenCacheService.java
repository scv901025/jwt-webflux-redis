package com.example.jwtredis.service;
import com.example.jwtredis.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.time.Duration;
@Slf4j @Service @RequiredArgsConstructor
public class TokenCacheService {
    private final ReactiveStringRedisTemplate redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;
    @Value("${app.redis.prefix.refresh-token}") private String refreshPrefix;
    @Value("${app.redis.prefix.user-tokens}") private String userTokensPrefix;
    public Mono<Boolean> saveRefreshToken(String username, String refreshToken) {
        return redisTemplate.opsForValue().set(refreshPrefix + username, refreshToken, Duration.ofSeconds(jwtTokenProvider.getRefreshExpirationInSeconds()));
    }
    public Mono<String> getRefreshToken(String username) { return redisTemplate.opsForValue().get(refreshPrefix + username); }
    public Mono<Boolean> isRefreshTokenValid(String username, String refreshToken) {
        return getRefreshToken(username).map(stored -> stored.equals(refreshToken)).defaultIfEmpty(false);
    }
    public Mono<Boolean> deleteRefreshToken(String username) { return redisTemplate.delete(refreshPrefix + username).map(c -> c > 0); }
    public Mono<Boolean> cacheAccessToken(String username, String accessToken) {
        return redisTemplate.opsForValue().set(userTokensPrefix + username, accessToken, Duration.ofSeconds(jwtTokenProvider.getAccessExpirationInSeconds()));
    }
    public Mono<String> getCachedAccessToken(String username) { return redisTemplate.opsForValue().get(userTokensPrefix + username); }
}