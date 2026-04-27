# jwt-webflux-redis

Spring WebFlux + JWT + Refresh Token + Redis Cache + Blacklist (Proyecto 2).

## Stack
- Java 21
- Spring Boot 3.2.5
- Spring WebFlux (reactivo)
- Spring Security
- JJWT 0.12.5
- Spring Data Redis Reactive (Lettuce)
- Lombok

## Requisitos previos
- Redis corriendo en localhost:6379
  ```bash
  docker run -d -p 6379:6379 redis:7-alpine
  ```

## Usuarios de prueba
| Usuario | Password   | Roles                  |
|---------|------------|------------------------|
| admin   | admin123   | ROLE_ADMIN, ROLE_USER  |
| user    | user123    | ROLE_USER              |

## Endpoints
| Método | Endpoint             | Auth     | Descripción                          |
|--------|----------------------|----------|--------------------------------------|
| POST   | /api/auth/login      | No       | Genera access token + refresh token  |
| POST   | /api/auth/refresh    | No       | Rota el refresh token                |
| POST   | /api/auth/logout     | Bearer   | Blacklist access + borra refresh     |
| GET    | /api/profile         | Bearer   | Perfil del usuario autenticado       |
| GET    | /api/admin/dashboard | ADMIN    | Panel de administracion              |

## Arquitectura Redis
```
refresh:{username}     → <refreshToken>    TTL: 7 dias
blacklist:{token}      → "revoked"         TTL: tiempo restante del token
user_tokens:{username} → <accessToken>     TTL: 15 minutos
```

## Flujo completo
```bash
# 1. Login
curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# 2. Usar access token
curl http://localhost:8081/api/profile \
  -H "Authorization: Bearer <access_token>"

# 3. Renovar tokens
curl -X POST http://localhost:8081/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

# 4. Logout
curl -X POST http://localhost:8081/api/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

## Ejecucion
```bash
mvn spring-boot:run
```
Servidor en: http://localhost:8081
