package com.example.jwtredis.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/profile")
    public Mono<ResponseEntity<Map<String, Object>>> getProfile(
            @AuthenticationPrincipal UserDetails userDetails) {
        return Mono.just(ResponseEntity.ok(Map.of(
                "username", userDetails.getUsername(),
                "roles", userDetails.getAuthorities()
                        .stream().map(a -> a.getAuthority()).toList()
        )));
    }

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> adminDashboard() {
        return Mono.just(ResponseEntity.ok(
                Map.of("message", "Panel de administracion - Solo ADMIN")));
    }
}
