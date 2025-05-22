package study.social_login.jwt;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Date;
import org.springframework.beans.factory.annotation.Value;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;

// 토큰 생성 및 검증
@Component  
public class JwtTokenProvider {
    @Value("${jwt.secret}")
    private String secretKey;

    // 액세스 토큰 생성
    public String createAccessToken(String email) {
        return createToken(email, Duration.ofMinutes(15));
    }

    // 리프레시 토큰 생성
    public String createRefreshToken(String email) {
        return createToken(email, Duration.ofDays(7));
    }


    // 토큰 생성
    public String createToken(String email, Duration duration) {
        Claims claims = Jwts.claims().setSubject(email);
        
        Date now = new Date();
        Date validity = new Date(now.getTime() + duration.toMillis());

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()), SignatureAlgorithm.HS256)
            .compact();
    }

    // 토큰에서 사용자 정보 추출
    public String getUsername(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(secretKey.getBytes())
            .build()
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    // 토큰 유효성 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(secretKey.getBytes()).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}

