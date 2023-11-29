package com.secu.jwt.common.checker;

import java.util.Map;
import java.util.function.Supplier;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import com.secu.jwt.vo.LoginInfoVO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class TeamParamAuthManager implements AuthorizationManager<RequestAuthorizationContext> {
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
		 
		LoginInfoVO login = (LoginInfoVO)SecurityContextHolder.getContext().getAuthentication().getPrincipal();

		log.info("login=>{}", login);
		int tiNum = Integer.parseInt(object.getRequest().getParameter("tiNum"));
		if(tiNum==1) {
			return new AuthorizationDecision(true);
		}
        return new AuthorizationDecision(false);
	}

}
