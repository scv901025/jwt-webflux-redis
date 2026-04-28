package com.example.jwtredis.controller;
import com.example.jwtredis.dto.*;
import com.example.jwtredis.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
@RestController @RequestMapping("/api/auth") @RequiredArgsConstructor
public class AuthController {
    private static final String BEARER_PREFIX = "Bearer ";
    private final AuthService authService;
    @PostMapping("/login")
    public Mono<ResponseEntity<TokenResponse>> login(@RequestBody LoginRequest request) {
        return authService.login(request).map(ResponseEntity::ok)
                .onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
    }
    @PostMapping("/refresh")
    public Mono<ResponseEntity<TokenResponse>> refresh(@RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request).map(ResponseEntity::ok)
                .onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
    }
    @PostMapping("/logout")
    public Mono<ResponseEntity<Void>> logout(ServerWebExchange exchange) {
        String h = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(h) || !h.startsWith(BEARER_PREFIX))
            return Mono.just(ResponseEntity.badRequest().build());
        return authService.logout(h.substring(BEARER_PREFIX.length()))
                .then(Mono.just(ResponseEntity.<Void>ok().build()))
                .onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).build()));
    }
}