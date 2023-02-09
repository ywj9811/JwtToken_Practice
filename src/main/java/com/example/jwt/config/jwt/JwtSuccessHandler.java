package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.config.secretKeys.TK_HEADER;
import com.example.jwt.domain.Profile;
import com.example.jwt.service.ProfileService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.example.jwt.config.secretKeys.TK_HEADER.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtSuccessHandler implements AuthenticationSuccessHandler {
    private final ProfileService profileService;

    //JwtAuthProvider에서 인증이 완료되면 여기가 실행됨
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("인증 완료 토큰 발급 시작");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        Profile profile = principalDetails.getProfile();

        String accessToken = JWT.create()
                .withSubject(profile.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + AT_EXP_TIME))
                .withClaim("role", profile.getRoles())
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .sign(Algorithm.HMAC256(SECRET));
        String refreshToken = JWT.create()
                .withSubject(profile.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + RT_EXP_TIME))
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .sign(Algorithm.HMAC256(SECRET));
        //ACCESS토큰, REFRESH토큰 발급
        
        //REFRESH 토큰 저장
        profileService.updateRefreshToken(profile.getUsername(), refreshToken);

        //ACCESS 토큰, REFRESH 토큰 프론트단에 Response header로 전달
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");
        response.setHeader("AC_TOKEN", accessToken);
        response.setHeader("RF_TOKEN", refreshToken);

        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("AT_TOKEN", MYKEY + " " + accessToken);
        responseMap.put("RT_TOKEN", MYKEY + " " + refreshToken);
        new ObjectMapper().writeValue(response.getWriter(), responseMap);
        //response에 반환함
    }
}
