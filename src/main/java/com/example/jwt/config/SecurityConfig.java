package com.example.jwt.config;

import com.example.jwt.config.jwt.*;
import com.example.jwt.service.ProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CorsConfig corsConfig;
    private final JwtSuccessHandler successHandler;
    private final JwtAuthorizationFilter authorizationFilter;
    private final JwtAuthProvider authProvider;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authProvider);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManagerBean());
        jwtAuthenticationFilter.setFilterProcessesUrl("/api/v1/login");
        jwtAuthenticationFilter.setAuthenticationSuccessHandler(successHandler);

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        //세션을 사용하지 않겠다. 라는 것이다.
                .and()
                .addFilter(corsConfig.corsFilter())
                //CorsConfig에서 설정한 필터로 등록하게 된다. (내가 설정한 부분에서는 인증을 사용하지 않을 것이다!)
                //자바스크립트로 요청받을 때 cors방지

//                .formLogin().disable()
                //기본적인 로그인 방식을 사용하지 않을 것이다!
//                .httpBasic().disable()
                //Basic 방식은 ID, PW를 가지고 요청하는 방식으로 해당 방식을 사용하지 않겠다는 것이다 = 대신에 토큰을 사용할 것이다.
                //따라서 기존의 로그인 방식을 사용하지 않기 위해서 formLogin과 httpBasic을 끄는 것이다.

                .addFilter(jwtAuthenticationFilter)
                //이렇게 수동으로 로그인 진행을 위한 필터를 달아줌 그럼 이제 /login으로 접근할 수 있음
                .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class)

                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }
}
