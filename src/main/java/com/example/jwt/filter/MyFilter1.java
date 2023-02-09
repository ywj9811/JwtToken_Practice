package com.example.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터2");
        chain.doFilter(request, response);

        //토큰이름 : cos
        /**
         * 이러한 토큰을 만드는 시점 : id, pw 정상적으로 들어와서 로그인이 완료되면 이제 토큰을 생성해서 그걸로 응답해줌
         * 그 이후
         * 요청할 때 마다 header에서 Authorization에 value값으로 토큰을 가지고 옴
         * 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨 (RSA와 같은 방식으로)
         */
//        if (req.getMethod().equals("POST")) {
//            String header = req.getHeader("Authorization");
//            System.out.println("Header = " + header);
//
//            if (header.equals("cos")) {
//                chain.doFilter(req,res);
//            } else {
//                PrintWriter out = res.getWriter();
//                out.println("인증 실패");
//            }
//        }
    }
}
