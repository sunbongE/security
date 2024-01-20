package com.example.security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;

//@RestController
public class JwtAuthenticationResource {

    private JwtEncoder jwtEncoder;

    // JwtAuthenticationResource 클래스의 생성자
    public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping("/authenticate")// Authentication 객체를 받아 JwtResponse를 반환하는 메서드
    public JwtResponse authentication(Authentication authentication) {
        // JwtResponse 객체를 생성하고 토큰을 담아 반환
        return new JwtResponse(createToken(authentication));
    }

    // Authentication을 기반으로 토큰을 생성하는 메서드
    private String createToken(Authentication authentication) {
        // JwtClaimsSet을 빌더를 사용하여 생성
        var claims = JwtClaimsSet.builder()
                .issuer("self") // 발행자 설정
                .issuedAt(Instant.now()) // 시스템에 현재의 인스턴스를 받았다고하는것.
                .expiresAt(Instant.now().plusSeconds(60 * 30)) // 만료일 30분으로 설정
                .subject(authentication.getName()) // 토큰 주제 설정
                .claim("scope", createScope(authentication)) // 사용자 권한(scope) 설정
                .build();

        // JwtEncoder를 사용하여 JwtEncoderParameters를 생성하고 토큰을 인코딩하여 반환
        return jwtEncoder.encode(JwtEncoderParameters.from(claims))
                .getTokenValue();
    }

    // Authentication에서 권한을 추출하여 공백으로 구분된 문자열로 반환하는 메서드
    private Object createScope(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.joining(" "));
    }


}

// JwtResponse를 나타내는 불변(immutable) 레코드(record) 선언
record JwtResponse(String token) {
}