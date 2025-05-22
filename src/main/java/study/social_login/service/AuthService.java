package study.social_login.service;

import org.springframework.http.ResponseEntity;
import jakarta.servlet.http.HttpServletResponse;
import study.social_login.dto.LoginRequestDto;
import study.social_login.dto.SignupRequestDto;

public interface AuthService {
    ResponseEntity<?> login(LoginRequestDto dto, HttpServletResponse response);
    ResponseEntity<?> signupWithEmail(SignupRequestDto dto);
}