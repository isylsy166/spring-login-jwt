package study.social_login.service;

import java.util.Collections;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
import study.social_login.dto.LoginRequestDto;
import study.social_login.jwt.JwtTokenProvider;
import study.social_login.repository.UserRepository;
import study.social_login.dto.SignupRequestDto;
import study.social_login.entities.User;


@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // 로그인
    @Override
    public ResponseEntity<?> login(LoginRequestDto dto, HttpServletResponse response) {
        // 사용자 이메일로 조회
        User user = userRepository.findByEmail(dto.getEmail())
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        // 비밀번호 검증
        if(!passwordEncoder.matches(dto.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("비밀번호가 일치하지 않습니다.");
        }

        // JWT 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(user.getEmail());
        String refreshToken = jwtTokenProvider.createRefreshToken(user.getEmail());

        // 리프레시 토큰을 쿠키에 저장
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7일

        response.addCookie(cookie);

        // 응답에 액세스 토큰 반환
        return ResponseEntity.ok(Collections.singletonMap("accessToken", accessToken));
    }

    // 회원가입
    @Override
    public ResponseEntity<?> signupWithEmail(SignupRequestDto dto) {
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("이미 존재하는 사용자입니다.");
        }

        String encodedPassword = passwordEncoder.encode(dto.getPassword());

        User user = User.builder()
                .email(dto.getEmail())
                .username(dto.getUsername())
                .password(encodedPassword)
                .role("USER")
                .build();

        userRepository.save(user);

        return ResponseEntity.ok("회원가입 성공");
    }



}
