package study.social_login.dto;

import lombok.Getter;

@Getter
public class SignupRequestDto {
    private String email;
    private String username;
    private String password;
    private String name;
}
