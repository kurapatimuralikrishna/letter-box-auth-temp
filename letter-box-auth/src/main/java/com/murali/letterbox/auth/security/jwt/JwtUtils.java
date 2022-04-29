package com.murali.letterbox.auth.security.jwt;

import java.util.Date;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.murali.letterbox.auth.model.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtUtils {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
	@Value("${murali.letterbox.app.jwtSecret}")
	private String jwtSecret;
	@Value("${murali.letterbox.app.jwtExpirationMs}")
	private int jwtExpirationMs;
	@Value("${murali.letterbox.app.jwtCookieName}")
	private String jwtCookie;

	public String getJwtFromCookie(HttpServletRequest request) {
		Cookie cookie = WebUtils.getCookie(request, jwtCookie);
		return (cookie != null) ? cookie.getValue() : null;
	}

	public String getUsernameFromToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}

	public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
		String jwt = generateTokenFromUsername(userPrincipal.getUsername());
		ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true)
				.build();
		return cookie;
	}

	public String generateTokenFromUsername(String username) {
		return Jwts.builder().setSubject(username).setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(SignatureAlgorithm.HS512, jwtSecret).compact();
	}
	
	public ResponseCookie getCleanCookie() {
		return ResponseCookie.from(jwtCookie,null).path("/api").build();
	}
	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
			return true;
		} catch (SignatureException e) {
			logger.error("Invalid jwt signature: {}", e.getMessage());
		} catch (MalformedJwtException e) {
			logger.error("Invalid jwt token: {}", e.getMessage());
		} catch (ExpiredJwtException e) {
			logger.error("Jwt token is expired: {}", e.getMessage());
		} catch (UnsupportedJwtException e) {
			logger.error("Jwt token is unsupported: {}", e.getMessage());
		} catch (IllegalArgumentException e) {
			logger.error("Jwt claims string is empty: {}", e.getMessage());
		}
		return false;
	}
}