package ctu.gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ctu.gateway.utils.ErrorResponse;
import ctu.gateway.utils.JwtUtil;  // Import JwtUtil
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.logging.Level;
import java.util.logging.Logger;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private String secretKey = "your_secret_key";

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            System.out.println("----------");
            String path = exchange.getRequest().getPath().toString();
            System.out.println(path);
            if (path.startsWith("/auth") || path.startsWith("/media") || path.startsWith("/events") || path.startsWith("/booking")  || path.startsWith("/payment") ) {
                return chain.filter(exchange); // Chỉ tiếp tục mà không cần kiểm tra token
            }
            String token = resolveToken(exchange);
            System.out.println(token);
            if (token == null) { // Sử dụng validateToken từ JwtUtil
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

    // Lấy role từ token sử dụng JwtUtil
    private boolean isAuthorized(String role, String path) {
        if (path.startsWith("/companies")) {
            // Vai trò COMPANY được phép truy cập
            return "COMPANY".equals(role);
        }
         if (path.startsWith("/submissions")) {
            // Vai trò COMPANY  được phép truy cập
            return "COMPANY".equals(role);
        }

        if (path.startsWith("/users")) {
            // Chỉ USER được phép truy cập
            return "USER".equals(role);
        }
        if (path.startsWith("/admin")) {
            // Chỉ ADMIN được phép truy cập
            return "ADMIN".equals(role);
        }
        // Mặc định không được phép
        return false;
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
        ErrorResponse errorResponse = new ErrorResponse(HttpStatus.FORBIDDEN.value(), "Forbiddennn");

        // Đảm bảo trả về JSON
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // Chuyển đổi ErrorResponse thành JSON và viết vào response body
        DataBuffer buffer = exchange.getResponse().bufferFactory()
                .wrap(new ObjectMapper().writeValueAsBytes(errorResponse));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    public String getRoleFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
        return (String) claims.get("role");
    }

    // Phương thức để lấy các claims từ JWT
    public static class Config {
        // Add configuration properties if needed
    }
}
