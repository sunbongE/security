package com.example.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class JwtSecurityConfiguration {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                auth -> {
                    auth.anyRequest().authenticated();
                });
        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS // 상태가 없는 REST API에서 csrf토큰, 세션사용안함 설정!
                        )
        );

//        http.formLogin();
        http.httpBasic();
        http.csrf().disable();
        http.headers().frameOptions().sameOrigin();
// oauth server setting
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); // 이후 디코더 설정
        return http.build();
    }

    //=============================================================
    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }
    //=============================================================


    // 사용자를 채우는 방법
    @Bean // UserDetailsService : 사용자별 데이터를 로드하는 코어 인터페이스
    public UserDetailsService userDetailsService(DataSource dataSource) {
        // 사용자 생성.
        var user = User.withUsername("user")
//                .password("{noop}dummy")
                .password("dummy")
                .passwordEncoder(str -> passwordEncoder().encode(str))// 단방향암호화
                .roles("USER")
                .build();

        var admin = User.withUsername("admin")
                .password("dummy")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("ADMIN", "USER")
                .build();

        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager; // InMemoryUserDetailsManager : UserDetailsManager의 비지속적 구현
    }
    //============================================================= db관련.

    // 비밀번호 암호화.
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public KeyPair keyPair() {
        try {
            var keyPairGenerator =
                    KeyPairGenerator.getInstance("RSA");
            // 키사이즈가 높을 수록 보안? 높아짐
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Bean
    public RSAKey rsaKey(KeyPair keyPair) {
        return new RSAKey
                .Builder((RSAPublicKey) keyPair.getPublic()) // 키페어에서 공개키를 가져온다.
                .privateKey(keyPair.getPrivate()) // 비밀키
                .keyID(UUID.randomUUID().toString()) // 키아이디 설정
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        var jwkSet = new JWKSet(rsaKey); // jwkset생성.
        return (jwkSelector, context)-> jwkSelector.select(jwkSet);
    }

    @Bean // 디코더 만들기.
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    @Bean // 인코더 만들기.
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){
        return new NimbusJwtEncoder(jwkSource);
    }
}
