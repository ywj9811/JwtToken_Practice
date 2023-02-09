package com.example.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.config.secretKeys.TK_HEADER;
import com.example.jwt.domain.Profile;
import com.example.jwt.domain.dto.ProfileDto;
import com.example.jwt.respository.ProfileRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.example.jwt.config.secretKeys.TK_HEADER.*;

@RequiredArgsConstructor
@Service
@Slf4j
@Transactional
public class ProfileService{
    private final ProfileRepo profileRepo;
    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    public Profile findByUsername(String username) {
        return profileRepo.findByUsername(username);
    }

    public Profile saveProfile(String username, String password, String role) {
        if (profileRepo.existsByUsername(username))
            return null;
        String encodePassword = bCryptPasswordEncoder.encode(password);
        Profile profile = ProfileDto.dtoToDomain(username, encodePassword, role);
        Profile save = profileRepo.save(profile);
        return save;
    }

    /**
     * Token 관련
     */
    
    public void updateRefreshToken(String username, String refreshToken) {
        Profile profile = profileRepo.findByUsername(username);
        profile.updateRefreshToken(refreshToken);
    }

    public Map<String, String> refresh(String refreshToken) {
        //Refresh 토큰 유효성 검사
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
        DecodedJWT decodedJWT = verifier.verify(refreshToken);

        //Access 토큰 재발급
        long now = System.currentTimeMillis();
        String username = decodedJWT.getSubject();
        Profile profile = profileRepo.findByUsername(username);
        if (profile == null)
            throw new UsernameNotFoundException("사용자X");

        String accessToken = JWT.create()
                .withSubject(profile.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + AT_EXP_TIME))
                .withClaim("role", profile.getRoles())
                .sign(Algorithm.HMAC256(SECRET));

        Map<String, String> accessTokenResponseMap = new HashMap<>();

        /**
         * 현재 시간과 Refresh Token 만료시간 계산해 1달 미만이면 재발급
         */
        long refreshExpireTime = decodedJWT.getClaim("exp").asLong() * 1000;
        long diffDays = (refreshExpireTime - now) / 1000 / (24 * 3600);
        long diffMin = (refreshExpireTime - now) / 1000 / 60;

        if (diffMin < 5) {
            String newRefreshToken = JWT.create()
                    .withSubject(profile.getUsername())
                    .withExpiresAt(new Date(now + RT_EXP_TIME))
                    .sign(Algorithm.HMAC256(SECRET));
            accessTokenResponseMap.put("RF_TOKEN", MYKEY + " " + newRefreshToken);
            profile.updateRefreshToken(newRefreshToken);
        }

        accessTokenResponseMap.put("AC_TOKEN", MYKEY + " " + accessToken);
        return accessTokenResponseMap;
    }
}
