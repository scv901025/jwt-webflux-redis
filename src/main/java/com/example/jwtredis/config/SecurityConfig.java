package com.example.jwtredis.config;
import com.example.jwtredis.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.*;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;
@Configuration @EnableWebFluxSecurity @EnableReactiveMethodSecurity @RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((e, ex2) -> Mono.fromRunnable(() -> e.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
                        .accessDeniedHandler((e, ex2) -> Mono.fromRunnable(() -> e.getResponse().setStatusCode(HttpStatus.FORBIDDEN))))
                .authorizeExchange(auth -> auth
                        .pathMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/refresh").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/auth/logout").authenticated()
                        .pathMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyExchange().authenticated())
                .addFilterBefore(jwtAuthenticationFilter, SecurityWebFilterOrder.AUTHENTICATION)
                .build();
    }
    @Bean public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
    @Bean
    public ReactiveAuthenticationManager authenticationManager(ReactiveUserDetailsService uds, PasswordEncoder pe) {
        var m = new UserDetailsRepositoryReactiveAuthenticationManager(uds);
        m.setPasswordEncoder(pe);
        return m;
    }
}