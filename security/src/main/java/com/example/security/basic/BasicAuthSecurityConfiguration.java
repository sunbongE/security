package com.example.security.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
//import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.jdbc.datasource.*;

import javax.sql.DataSource;

//@Configuration
public class BasicAuthSecurityConfiguration {
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

        return http.build();
    }

//    @Bean // UserDetailsService : 사용자별 데이터를 로드하는 코어 인터페이스
//    public UserDetailsService userDetailsService(){
//        // 사용자 생성.
//       var user = User.withUsername("user")
//                .password("{noop}dummy")
//                .roles("USER")
//                .build();
//
//       var admin = User.withUsername("admin")
//                .password("{noop}dummy")
//                .roles("ADMIN")
//                .build();
////        return new InMemoryUserDetailsManager(); // InMemoryUserDetailsManager : UserDetailsManager의 비지속적 구현
//        return new InMemoryUserDetailsManager(user, admin); // InMemoryUserDetailsManager : UserDetailsManager의 비지속적 구현
//    }

    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }


    // 사용자를 채우는 방법
    @Bean // UserDetailsService : 사용자별 데이터를 로드하는 코어 인터페이스
    public UserDetailsService userDetailsService(DataSource dataSource){
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
                .roles("ADMIN","USER")
                .build();

       var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager; // InMemoryUserDetailsManager : UserDetailsManager의 비지속적 구현
    }

    // 비밀번호 암호화.
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


}
