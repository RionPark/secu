package com.secu.jwt.common.handler;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.secu.jwt.common.provider.JWTProvider;
import com.secu.jwt.vo.LoginInfoVO;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthSuccessHandler implements AuthenticationSuccessHandler {

	private final JWTProvider jwtProvider;
	private int expire;
	
	
	public void setExpire(@Value("${jwt.expire}")int expire) {
		this.expire = expire;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		// TODO Auto-generated method stub
		LoginInfoVO login = (LoginInfoVO) authentication.getPrincipal();
		String token = jwtProvider.generateJWT(login);
        ResponseCookie resCookie = ResponseCookie.from("Authorization", token)
                .httpOnly(true)
                .sameSite("None")
                .secure(true)
                .path("/")
                .maxAge(Math.toIntExact(expire))
                .build();
        response.addHeader("Set-Cookie", resCookie.toString());
        response.sendRedirect("/");
	}

}
