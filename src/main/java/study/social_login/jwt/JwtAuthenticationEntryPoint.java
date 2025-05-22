package study.social_login.jwt;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/*
 * JWT 인증 시스템에서 인증 실패(401 Unauthorized)가 발생했을 대, 응답을 정의하는 클래스
 * 요청에 JWT가 없어나(만료, 조작, 구조이상 등)
 * SecurityContext에 인증 정보가 없을 때
 * → Security가 “이건 인증 안 된 사용자야”라고 판단함
 * → AuthenticationEntryPoint가 호출됨
 * 사용자 친화적인 메지지 제공
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        System.out.println("🚨 JwtAuthenticationEntryPoint invoked!");

        
        // 이미 응답 나갔으면 종료
        if (response.isCommitted()) {
            return;
        }

        response.resetBuffer(); // 버퍼 초기화
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        body.put("status", 401);
        body.put("error", "Unauthorized");
        body.put("message", "인증이 필요합니다. JWT 토큰을 확인해주세요.");
        body.put("path", request.getRequestURI());

        String responseBody = objectMapper.writeValueAsString(body);
        response.getWriter().write(responseBody);
        response.flushBuffer(); // 여기 중요!!
    }
}

