package ctu.gateway.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.ArrayList;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    // Thời gian hết hạn token (15 phút)
    @Value("${jwt.expiration}")
    private long EXPIRATION_TIME;


    // Trích xuất username (email) từ token
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    // Trích xuất role từ token
    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    // Trích xuất userId từ token
    public String extractUserId(String token) {
        return extractAllClaims(token).get("userId", String.class);
    }

    // Kiểm tra token có hết hạn không
    public boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    // Kiểm tra token có hợp lệ không (so sánh email hoặc id)
    public boolean validateToken(String token, String expectedEmail) {
        final String username = extractUsername(token);
        return (username.equals(expectedEmail) && !isTokenExpired(token));
    }

    // Trích xuất tất cả claims
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }
}
