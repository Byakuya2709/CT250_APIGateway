/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ctu.gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ctu.gateway.utils.ErrorResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 *
 * @author admin
 */
@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Value("${jwt.secret}")
    private String secretKey;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            System.out.println("----------");
            String path = exchange.getRequest().getPath().toString();
            
            if (path.startsWith("/auth") || path.startsWith("/user")) {
                return chain.filter(exchange); // Chỉ tiếp tục mà không cần kiểm tra token
            }
            String token = resolveToken(exchange);

            if (token == null || !validateToken(token)) {
                try {
                    return handleUnauthorized(exchange);
                } catch (JsonProcessingException ex) {
                    Logger.getLogger(JwtAuthenticationFilter.class.getName()).log(Level.SEVERE, null, ex);
                    exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                }
            }

            // Lấy role từ token
            String role = getRoleFromToken(token);

            System.out.println(role);
            // Kiểm tra role với route
            if (!isAuthorized(role, path)) {
                try {
                    return handleForbidden(exchange);
                } catch (JsonProcessingException ex) {
                    Logger.getLogger(JwtAuthenticationFilter.class.getName()).log(Level.SEVERE, null, ex);
                    exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                }
            }

            return chain.filter(exchange);
        };
    }

    private String resolveToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            return false;
        }
    }

    private String getRoleFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
        return claims.get("role", String.class);
    }

    private boolean isAuthorized(String role, String path) {
        if (path.startsWith("/auth") || path.startsWith("/otp")) {
            return true; // Public route
        }
        if (path.startsWith("/user") && "USER".equals(role)) {
            return true; // USER role
        }
        if (path.startsWith("/admin") && "ADMIN".equals(role)) {
            return true; // ADMIN role
        }
        return false; // Unauthorized
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange) throws JsonProcessingException {
        // Tạo ErrorResponse với thông tin lỗi
        ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), "Unauthorized");

        // Đảm bảo trả về JSON
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // Chuyển đổi ErrorResponse thành JSON và viết vào response body
        DataBuffer buffer = exchange.getResponse().bufferFactory()
                .wrap(new ObjectMapper().writeValueAsBytes(errorResponse));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    private Mono<Void> handleForbidden(ServerWebExchange exchange) throws JsonProcessingException {
        ErrorResponse errorResponse = new ErrorResponse(HttpStatus.FORBIDDEN.value(), "Forbidden");

        // Đảm bảo trả về JSON
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // Chuyển đổi ErrorResponse thành JSON và viết vào response body
        DataBuffer buffer = exchange.getResponse().bufferFactory()
                .wrap(new ObjectMapper().writeValueAsBytes(errorResponse));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    public static class Config {
        // Add configuration properties if needed
    }

}
