package com.example.jwt.config.auth;

import com.example.jwt.domain.Profile;
import com.example.jwt.respository.ProfileRepo;
import com.example.jwt.service.ProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 기존에는 formLogin에 따라서 http://localhost8080/login 접근시 자동으로 동작함
 * 하지만 현재 formLogin.disable 을 했기 때문에 이제 자동으로 접근하지 못함
 */
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final ProfileService profileService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService 실행");
        Profile profile = profileService.findByUsername(username);
        if (profile == null) {
            throw new UsernameNotFoundException("PrincipalDetailsService - loadUserByname : 사용자 X");
        }
        System.out.println("조회" + profile);
        return new PrincipalDetails(profile);
    }
}
