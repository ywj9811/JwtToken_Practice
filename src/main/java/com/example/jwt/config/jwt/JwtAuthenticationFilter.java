package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.domain.Profile;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 로그인 처리하는 클래스!!!
 */

/**
 * 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 존재하는데
 * 이는 login 요청해서 username, password 전송하면 자동으로 동작함
 * 하지만 현재 자동으로 동작하지 않음 (formLogin이 중지되어서)
 * 따라서 내가 수동으로 동작하고자 SecurityConfig에 등록
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    /**
     * 로그인 요청시 아래의 메소드가 동작함
     *
     * 1. username, password 받아서
     * 2. 정상인지 로그인 시도를 함 : authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출됨
     *      이어서 loadUserByUsername() 실행
     *
     * 3. 완료 후 PrincipalDetails를 세션에 담고 (권한 관리를 위해서)
     * 4. JWT 발급
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter 동작");

        //json으로 넘어오는 것을 받기 위해서 ObjectMapper 사용
        ObjectMapper om = new ObjectMapper();
        Profile profile = null;
        try {
            profile = om.readValue(request.getInputStream(), Profile.class);
            System.out.println(profile);
        } catch (IOException e) {
            e.printStackTrace();
        }
        //Json타입으로 받게 되면 ObjectMapper.readValue(request.getInputStream(), 원하는 객체) 이렇게 하면 받을 수 있다.

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(profile.getUsername(), profile.getPassword());
        System.out.println("인증 시작");
        /**
         * id, pw 담긴 토큰 생성
         */
        
        //아래 코드가 실행되면 PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        //비밀번호가 틀리면 여기서 짤림

        //Authentication 객체가 session 영역에 저장이 되었다 : 로그인 되었음
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("인증 통과 : Profile : " + principalDetails.getProfile().getUsername() + ", " + principalDetails.getProfile().getPassword());

        return authentication;
        //authentication 리턴이 되면 authentication을 세션에 저장함
        // 리턴하는 이유는 권한 관리를 security가 대신 해주고 있기 때문에 편리함을 위해서이다.
        // JWT를 사용하기 때문에 굳이 세션을 만들 필요는 없다. 단지 편리하기 위해서 세션을 만드는 중임
    }
}
