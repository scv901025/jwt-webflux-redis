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
public class TokenBlacklistService {
    private final ReactiveStringRedisTemplate redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;
    @Value("${app.redis.prefix.blacklist}") private String blacklistPrefix;
    public Mono<Boolean> blacklistToken(String token) {
        long ttl = jwtTokenProvider.getRemainingTtlSeconds(token);
        if (ttl <= 0) return Mono.just(true);
        return redisTemplate.opsForValue().set(blacklistPrefix + token, "revoked", Duration.ofSeconds(ttl))
                .doOnSuccess(r -> log.info("Token en blacklist por {}s", ttl));
    }
    public Mono<Boolean> isBlacklisted(String token) { return redisTemplate.hasKey(blacklistPrefix + token); }
    public Mono<Boolean> isNotBlacklisted(String token) { return isBlacklisted(token).map(b -> !b); }
}