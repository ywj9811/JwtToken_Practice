//package com.example.jwt.config;
//
//import com.example.jwt.filter.MyFilter1;
//import com.example.jwt.filter.MyFilter2;
//import org.springframework.boot.web.servlet.FilterRegistrationBean;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class FilterConfig {
//    //수동 필터 생성 : 이는 기본적으로 시큐리티 필터보다 늦게 실행됨
//    //만약 먼저 실행시키고 싶으면 SecurityConfig에서 addFilterBefore()로 등록해야 한다.
//    @Bean
//    public FilterRegistrationBean<MyFilter1> filter1() {
//        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
//        bean.addUrlPatterns("/*");
//        bean.setOrder(0);
//        //.setOrder는 우선순위를 결정해 주는 것으로 낮을수록 높다.
//        return bean;
//    }
//
//    @Bean
//    public FilterRegistrationBean<MyFilter2> filter2() {
//        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
//        bean.addUrlPatterns("/*");
//        bean.setOrder(1);
//        //.setOrder는 우선순위를 결정해 주는 것으로 낮을수록 높다.
//        return bean;
//    }
//}
