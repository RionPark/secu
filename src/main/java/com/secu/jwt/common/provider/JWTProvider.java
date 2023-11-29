package com.secu.jwt.common.provider;

import java.security.Key;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.secu.jwt.mapper.LoginInfoMapper;
import com.secu.jwt.mapper.RoleInfoMapper;
import com.secu.jwt.vo.LoginInfoVO;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JWTProvider {

	private final String secret;
	private final int expire;
	private final LoginInfoMapper loginMapper;
	private final RoleInfoMapper roleMapper;
	
	public JWTProvider(@Value("${jwt.secret}") String secret
			,@Value("${jwt.expire}") int expire
			, @Autowired LoginInfoMapper loginMapper
			, @Autowired RoleInfoMapper roleMapper) {
		this.secret = secret;
		this.expire = expire;
		this.loginMapper = loginMapper;
		this.roleMapper = roleMapper;
	}
	
	public int getExpire() {
		return expire;
	}
	public String generateJWT(LoginInfoVO login) {
		Map<String,Object> claims = new HashMap<>();
		claims.put("liId", login.getLiId());
		claims.put("liName", login.getLiName());
		claims.put("liNum", login.getLiNum());
		claims.put("authorities", login.getAuthorities());
		Calendar c = Calendar.getInstance();
		c.add(Calendar.MILLISECOND, expire);
		byte[] bytes = DatatypeConverter.parseBase64Binary(secret);
		Key key = new SecretKeySpec(bytes, SignatureAlgorithm.HS256.getJcaName());
		JwtBuilder jb = Jwts.builder()
				.setClaims(claims)
				.signWith(SignatureAlgorithm.HS256, key)
				.setExpiration(c.getTime());
		return jb.compact();
	}

	public String generateJWT(String liId) {
		Map<String,Object> claims = new HashMap<>();

		LoginInfoVO login = loginMapper.selectLoginInfoByLiId(liId);
		login.setAuthorities(roleMapper.selectRoleInfosByLiNum(login.getLiNum()));
		
		claims.put("liId", login.getLiId());
		claims.put("liName", login.getLiName());
		claims.put("liNum", login.getLiNum());
		claims.put("authorities", login.getAuthorities());
		Calendar c = Calendar.getInstance();
		c.add(Calendar.MILLISECOND, expire);
		byte[] bytes = DatatypeConverter.parseBase64Binary(secret);
		Key key = new SecretKeySpec(bytes, SignatureAlgorithm.HS256.getJcaName());
		JwtBuilder jb = Jwts.builder()
				.setClaims(claims)
				.signWith(SignatureAlgorithm.HS256, key)
				.setExpiration(c.getTime());
		return jb.compact();
	}
	
	private Claims getClaims(String token) {

		byte[] bytes = DatatypeConverter.parseBase64Binary(secret);
		Key key = new SecretKeySpec(bytes, SignatureAlgorithm.HS256.getJcaName());
		Claims claims = Jwts.parser().setSigningKey(key)
				.parseClaimsJws(token).getBody();
		return claims;
	}
	
	public boolean validateJWT(String token) {
		try {
			getClaims(token);
			return true;
		}catch(Exception e) {
			throw e;
		}
	}
	
	public String getId(String token) {
		Claims claims = getClaims(token);
		return claims.get("liId").toString();
	}
	
	public LoginInfoVO getLogin(String token) {
		if(validateJWT(token)) {
			String liId = getId(token);
			LoginInfoVO login = loginMapper.selectLoginInfoByLiId(liId);
			login.setAuthorities(roleMapper.selectRoleInfosByLiNum(login.getLiNum()));
			return login;
		}
		return null;
	}
}
