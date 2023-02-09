package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.domain.Profile;
import com.example.jwt.service.ProfileService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있다.
 * 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 타게 되어있음
 * 만약 권한이나 인증이 필요한 주소가 아니라면 위의 필터를 거치지 않음
 */

public class NotUse1 extends BasicAuthenticationFilter {
    private ProfileService profileService;

    public NotUse1(AuthenticationManager authenticationManager, ProfileService profileService) {
        super(authenticationManager);
        this.profileService = profileService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증 확인");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : " + jwtHeader);

        //JWT 토큰 검증을 통해 정상적인 사용자인지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
            //이상하면 더이상 진행하지 않고 필터로 넘기고 끝냄
        }

        System.out.println("정상 토큰 받음 이어서 진행");

        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        String username = JWT.require(Algorithm.HMAC512("cos"))
                .build()
                .verify(jwtToken)
                .getClaim("username")
                .asString();
            //JwtAuthenticationFilter 에서 .sign 에 넣은 값으로 확인(secret키)

        if (username != null) {
            System.out.println("정상 유저 접근");

            Profile profile = profileService.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(profile);

            //JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            //Authentication 객체를 수동으로 만들어줌 (자동으로 Override 하면 로그인 처리가 완료되어 하는 부분임) 따라서 수동으로 임시로 생성

            SecurityContextHolder.getContext().setAuthentication(authentication);
                    //세션 공간임 : 강제로 시큐리티 세션에 접근하여 Authentication공간에 접근하여 만들어줌
        }

        chain.doFilter(request, response);
    }
}
/**
 * 현재 JwtAuthProvider가 대체 할 듯
 */