package com.murali.letterbox.auth.security.jwt;



import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.murali.letterbox.auth.model.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtUtils {
	private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);
	@Value("${murali.letterbox.app")
	private String jwtSecret;
	@Value("${murali.letterbox.app.jwtExpirationMs")
	private String jwtExpirationMs;
	@SuppressWarnings("deprecation")
	public String generateJwtToken(Authentication auth) {
		UserDetailsImpl userPrincipal = (UserDetailsImpl) auth.getPrincipal();
		return Jwts.builder()
				.setSubject(userPrincipal.getUsername())
				.setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(SignatureAlgorithm.HS512, jwtSecret)
				.compact();
	}
	public String getUsernameFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}
	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parser().setSigningKey(authToken).parseClaimsJws(authToken);
			return true;
		}
		catch (SignatureException e) {
			LOGGER.error("Invalid jwt signature: {}",e.getMessage());
		}
		catch (MalformedJwtException e) {
			LOGGER.error("Invalid jwt token: {}",e.getMessage());
		}
		catch (ExpiredJwtException e) {
			LOGGER.error("Jwt token is expired: {}",e.getMessage());
		}
		catch (UnsupportedJwtException e) {
			LOGGER.error("Jwt token is unsupported: {}",e.getMessage());
		}
		catch (IllegalArgumentException e) {
			LOGGER.error("Jwt claims string is empty: {}",e.getMessage());
		}
		return false;
	}
}