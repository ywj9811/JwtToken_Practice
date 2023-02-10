package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.domain.Profile;
import com.example.jwt.service.ProfileService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.example.jwt.config.secretKeys.TK_HEADER.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private final ProfileService profileService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String servletPath = request.getServletPath();
        String authorizationHeader = request.getHeader("Authorization");
        
        if (servletPath.equals("/api/v1/login") || servletPath.equals("/api/refresh")) {
            filterChain.doFilter(request, response);
            //해당 경로로 들어오면 토큰 검사 없이 그냥 지나가면 됨
        } else if ((authorizationHeader == null) || !authorizationHeader.startsWith(MYKEY)) {
            // 토큰값이 없거나 정상적이지 않다면 400 오류
            log.info("CustomAuthorizationFilter : JWT Token이 존재하지 않습니다.");
            response.setStatus(400);
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("utf-8");
            Map<Integer, String> errorResponse = new HashMap<>();
            errorResponse.put(400, "JWT Token이 존재하지 않습니다.");
            new ObjectMapper().writeValue(response.getWriter(), errorResponse);
        } else {
            try {
                //Access 토큰만 꺼내옴
                String accessToken = authorizationHeader.replace(MYKEY + " ", "");

                //검증
                JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
                DecodedJWT decodedJWT = verifier.verify(accessToken);

                //토큰에서 Claim의 Authorities 꺼내서 Authentication 객체 생성 , SecurityContext 저장
                Profile profile = profileService.findByUsername(decodedJWT.getSubject());
                PrincipalDetails principalDetails = new PrincipalDetails(profile);

                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(principalDetails.getUsername(), null, principalDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                filterChain.doFilter(request, response);
            } catch (TokenExpiredException e) {
                log.info("JwtAuthorizationFilter : Access토큰 만료");
                response.setStatus(401);
                response.setContentType(APPLICATION_JSON_VALUE);
                response.setCharacterEncoding("utf-8");
                Map<Integer, String> errorResponse = new HashMap<>();
                errorResponse.put(401, "Access Token이 만료되었습니다.");
                new ObjectMapper().writeValue(response.getWriter(), errorResponse);
            } catch (Exception e) {
                e.printStackTrace();
                log.info("CustomAuthorizationFilter : JWT 토큰이 잘못되었습니다. message : {}", e.getMessage());
                response.setStatus(400);
                response.setContentType(APPLICATION_JSON_VALUE);
                response.setCharacterEncoding("utf-8");
                Map<Integer, String> errorResponse = new HashMap<>();
                errorResponse.put(400, "잘못된 JWT Token 입니다.");
                new ObjectMapper().writeValue(response.getWriter(), errorResponse);
            }
        }
    }
}
