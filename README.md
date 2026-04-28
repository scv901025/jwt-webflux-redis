# jwt-webflux-redis

Spring WebFlux + Spring Security + JWT + Refresh Token + Redis Cache + Blacklist

## Requisitos
- Java 21
- Maven
- Redis (local o Docker)

## Iniciar Redis con Docker
docker run -d -p 6379:6379 redis:7-alpine

## Usuarios de prueba
| Usuario | Contrasena | Roles |
|---------|-----------|-------|
| admin | admin123 | ROLE_ADMIN, ROLE_USER |
| user | user123 | ROLE_USER |

## Endpoints
| Metodo | Endpoint | Auth | Descripcion |
|--------|----------|------|-------------|
| POST | /api/auth/login | No | Access + Refresh token |
| POST | /api/auth/refresh | No | Rota refresh token |
| POST | /api/auth/logout | Bearer | Blacklist + borra refresh |
| GET | /api/profile | Bearer | Perfil del usuario |
| GET | /api/admin/dashboard | Bearer (ADMIN) | Panel admin |

## Ejecutar
mvn spring-boot:run
