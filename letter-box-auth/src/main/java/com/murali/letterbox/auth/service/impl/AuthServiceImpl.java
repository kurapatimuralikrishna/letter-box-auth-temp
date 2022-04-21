package com.murali.letterbox.auth.service.impl;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import com.murali.letterbox.auth.model.ERole;
import com.murali.letterbox.auth.model.Role;
import com.murali.letterbox.auth.model.User;
import com.murali.letterbox.auth.model.UserDetailsImpl;
import com.murali.letterbox.auth.payload.request.LoginRequest;
import com.murali.letterbox.auth.payload.request.SignupRequest;
import com.murali.letterbox.auth.payload.response.MessageResponse;
import com.murali.letterbox.auth.payload.response.UserInfoResponse;
import com.murali.letterbox.auth.repository.RoleRepository;
import com.murali.letterbox.auth.repository.UserRepository;
import com.murali.letterbox.auth.security.jwt.JwtUtils;
import com.murali.letterbox.auth.service.AuthService;

@Service
public class AuthServiceImpl implements AuthService {
	@Autowired
	AuthenticationManager authManager;
	@Autowired
	UserRepository userRepository;
	@Autowired
	RoleRepository roleRepository;
	@Autowired
	PasswordEncoder encoder;
	@Autowired
	JwtUtils jwtUtils;
	public ResponseEntity<?> authenticateUser(LoginRequest loginRequest) {
		Authentication auth = authManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(auth);
		UserDetailsImpl userDetails = (UserDetailsImpl) auth.getPrincipal();
	    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
		List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
				.collect(Collectors.toList());
		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
		        .body(new UserInfoResponse(userDetails.getId(), 
				userDetails.getUsername(), 
				userDetails.getEmail(),
				roles));
	}
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signup) {
		if(userRepository.existsByUsername(signup.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error:Username already exists"));
		}
		if(userRepository.existsByEmail(signup.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error:Email already exists"));
		}
		User user = new User(signup.getUsername(),signup.getEmail(),encoder.encode(signup.getPassword()));
		Set<String> strRoles = signup.getRoles();
		Set<Role> roles = new HashSet<>();
		
		if(strRoles == null) {
			Role urole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(()-> new RuntimeException("Error: Role is not found"));
			roles.add(urole);
		}
		//If I send a signup request for admin role, will I be able to braech?
		//Only an admin should be able to create another admin/mod.
		else {
			strRoles.forEach(role -> {
				Role urole;
				switch(role){
					case "admin":
						urole = roleRepository.findByName(ERole.ROLE_ADMIN)
						.orElseThrow(()-> new RuntimeException("Error: Role is not found"));
						roles.add(urole);
						break;
					case "mod":
						urole = roleRepository.findByName(ERole.ROLE_MOD)
						.orElseThrow(()-> new RuntimeException("Error: Role is not found"));
						roles.add(urole);
						break;
					default:
						urole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found"));
						roles.add(urole);
						break;
				}
			});
		}
		user.setRoles(roles);
		userRepository.save(user);
		return ResponseEntity.ok(new MessageResponse("User registered successfully"));
	}
	@Override
	public ResponseEntity<?> logoutUser() {
	    ResponseCookie cookie = jwtUtils.getCleanCookie();
	    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
	        .body(new MessageResponse("You've been signed out!"));
	}
}
