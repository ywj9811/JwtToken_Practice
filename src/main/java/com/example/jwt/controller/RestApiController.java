package com.example.jwt.controller;

import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.config.secretKeys.TK_HEADER;
import com.example.jwt.domain.Profile;
import com.example.jwt.respository.ProfileRepo;
import com.example.jwt.service.ProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Map;

import static com.example.jwt.config.secretKeys.TK_HEADER.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class RestApiController {
    private final ProfileService profileService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home() {
        return "<h1>home<h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token<h1>";
    }

    @PostMapping("/join")
    public String join(String username, String password) {
        Profile profile = profileService.saveProfile(username, password, "ROLE_USER");
        if (profile == null)
            return "실패";
        return "완료";
    }

    @GetMapping("/v1/user")
    public String user(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        System.out.println("authentication : " + principal);
        return "user";
    }
    @GetMapping("/v1/manager")
    public String manager() {
        return "manager";
    }
    @GetMapping("/v1/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(HttpServletRequest request, HttpServletResponse response) {
        String authorizationHeader = request.getHeader("Authorization");

        if ((authorizationHeader == null) || !authorizationHeader.startsWith(MYKEY)) {
            throw new RuntimeException("JWT Token이 존재하지 않습니다.");
        }
        String refreshToken = authorizationHeader.replace(MYKEY + " ", "");
        Map<String, String> tokens = profileService.refresh(refreshToken);
        response.setHeader("AC_TOKEN", tokens.get("AC_TOKEN"));
        if (tokens.get("RF_TOKEN") != null) {
            response.setHeader("RF_TOKEN", tokens.get("RF_TOKEN"));
        }
        return ResponseEntity.ok(tokens);
    }
}
