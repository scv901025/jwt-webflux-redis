package com.example.jwtredis.security;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
@Slf4j @Service
public class CustomUserDetailsService implements ReactiveUserDetailsService {
    private final Map<String, UserDetails> users = new ConcurrentHashMap<>();
    public CustomUserDetailsService(PasswordEncoder passwordEncoder) {
        users.put("admin", build("admin", passwordEncoder.encode("admin123"), List.of("ROLE_ADMIN","ROLE_USER")));
        users.put("user", build("user", passwordEncoder.encode("user123"), List.of("ROLE_USER"));
    }
    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return Mono.justOrEmpty(users.get(username))
                .switchIfEmpty(Mono.error(new UsernameNotFoundException("Usuario no encontrado: " + username)));
    }
    private UserDetails build(String u, String p, List<String> roles) {
        return new User(u, p, roles.stream().map(SimpleGrantedAuthority::new).toList());
    }
}