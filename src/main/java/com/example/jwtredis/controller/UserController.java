package com.example.jwtredis.controller;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import java.util.Map;
@RestController @RequestMapping("/api")
public class UserController {
    @GetMapping("/profile")
    public Mono<ResponseEntity<Map<String, Object>>> getProfile(@AuthenticationPrincipal UserDetails u) {
        return Mono.just(ResponseEntity.ok(Map.of("username", u.getUsername(),
                "roles", u.getAuthorities().stream().map(a -> a.getAuthority()).toList())));
    }
    @GetMapping("/admin/dashboard") @PreAuthorize("hasRole('ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> adminDashboard() {
        return Mono.just(ResponseEntity.ok(Map.of("message", "Panel de administracion - Solo ADMIN")));
    }
}