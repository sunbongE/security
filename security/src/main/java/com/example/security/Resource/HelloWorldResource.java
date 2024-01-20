package com.example.security.Resource;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class HelloWorldResource {

    @GetMapping("/")
    public String helloWord(Authentication authentication){
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // 사용자의 이메일과 이름 추출
        String userEmail = userDetails.getUsername(); // 이메일
        String userName = userDetails.getUsername(); // 이름

        System.out.println("User Email: " + userEmail);
        System.out.println("User Name: " + userName);
        System.out.println("userDetails: " + userDetails);

        return "HelloWorld'구글로그인성공";
    }
//    OAuth2AuthenticationToken [Principal=Name: [110994810525405490647], Granted Authorities: [[OIDC_USER, SCOPE_https://www.googleapis.com/auth/userinfo.email, SCOPE_https://www.googleapis.com/auth/userinfo.profile, SCOPE_openid]], User Attributes: [{at_hash=gi6vXBTnS8rOp7gjgxKdbQ, sub=110994810525405490647, email_verified=true, iss=https://accounts.google.com, given_name=Taeho, locale=ko, nonce=EAgol94KEI7L0fxUlY3zni_AjCLfPy1asW15-zvpAuY, picture=https://lh3.googleusercontent.com/a/ACg8ocI5OUQMPrdXHee1A5vlT-aHBbTlZLOZNaOHiJbzk65NXw=s96-c, aud=[78717585088-5slnk7cm1sh6m82jou6dk6vc12j2tg9d.apps.googleusercontent.com], azp=78717585088-5slnk7cm1sh6m82jou6dk6vc12j2tg9d.apps.googleusercontent.com, name=Taeho Park, exp=2024-01-20T07:26:18Z, family_name=Park, iat=2024-01-20T06:26:18Z, email=qkrxogh7@gmail.com}], Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=0:0:0:0:0:0:0:1, SessionId=33D237B2EB68B02DCD25123EF08226C8], Granted Authorities=[OIDC_USER, SCOPE_https://www.googleapis.com/auth/userinfo.email, SCOPE_https://www.googleapis.com/auth/userinfo.profile, SCOPE_openid]]
//    Name: [110994810525405490647], Granted Authorities: [[OIDC_USER, SCOPE_https://www.googleapis.com/auth/userinfo.email, SCOPE_https://www.googleapis.com/auth/userinfo.profile, SCOPE_openid]], User Attributes: [{at_hash=gi6vXBTnS8rOp7gjgxKdbQ, sub=110994810525405490647, email_verified=true, iss=https://accounts.google.com, given_name=Taeho, locale=ko, nonce=EAgol94KEI7L0fxUlY3zni_AjCLfPy1asW15-zvpAuY, picture=https://lh3.googleusercontent.com/a/ACg8ocI5OUQMPrdXHee1A5vlT-aHBbTlZLOZNaOHiJbzk65NXw=s96-c, aud=[78717585088-5slnk7cm1sh6m82jou6dk6vc12j2tg9d.apps.googleusercontent.com], azp=78717585088-5slnk7cm1sh6m82jou6dk6vc12j2tg9d.apps.googleusercontent.com, name=Taeho Park, exp=2024-01-20T07:26:18Z, family_name=Park, iat=2024-01-20T06:26:18Z, email=qkrxogh7@gmail.com}]

    Logger logger = LoggerFactory.getLogger(getClass())	;


    record Todo (String username, String description){}
    private static final List<Todo> TODO_LIST=
            List.of(new Todo("admin","learn AWS"),
                    new Todo("admin","get AWS Certified"));

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos(){
        return TODO_LIST;
    }

    @GetMapping("/users/{username}/todo")
// @GetMapping 어노테이션은 HTTP GET 요청에 대한 핸들러 메서드를 매핑합니다.
// "/users/{username}/todo" 경로로 들어오는 GET 요청을 이 메서드가 처리합니다.
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
// @PreAuthorize 어노테이션은 메서드 실행 전에 보안 검사를 수행합니다.
// 현재 사용자가 'USER' 역할을 가지고 있고, 요청의 username과 현재 인증된 사용자의 이름이 일치하는지 확인합니다.
    @PostAuthorize("returnObject.username =='admin'")
// @PostAuthorize 어노테이션은 메서드 실행 후에 추가적인 보안 검사를 수행합니다.
// 메서드의 반환값인 Todo 객체의 username이 'admin'과 일치하는지 확인합니다.
    @RolesAllowed({"ADMIN","USER"}) //설정한 역할중 하나라도 만족하면 통과된다.
    public Todo retrieveTodosForSpecificUser(@PathVariable String username){

        return TODO_LIST.get(0);
    }

    @PostMapping("/users/{username}/todo")
    public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo){
        logger.info("Create {} for {}", todo, username);
    }

}
