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
public class TokenBlacklistService {

    private final ReactiveStringRedisTemplate redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;

    @Value("${app.redis.prefix.blacklist}")
    private String blacklistPrefix;

    public Mono<Boolean> blacklistToken(String token) {
        long ttlSeconds = jwtTokenProvider.getRemainingTtlSeconds(token);
        if (ttlSeconds <= 0) {
            log.debug("Token ya expirado, no se agrega a blacklist");
            return Mono.just(true);
        }
        String key = blacklistPrefix + token;
        return redisTemplate.opsForValue()
                .set(key, "revoked", Duration.ofSeconds(ttlSeconds))
                .doOnSuccess(r -> log.info("Token agregado a blacklist por {}s", ttlSeconds));
    }

    public Mono<Boolean> isBlacklisted(String token) {
        String key = blacklistPrefix + token;
        return redisTemplate.hasKey(key)
                .doOnNext(exists -> {
                    if (exists) log.warn("Token en blacklist detectado");
                });
    }

    public Mono<Boolean> isNotBlacklisted(String token) {
        return isBlacklisted(token).map(blacklisted -> !blacklisted);
    }
}
