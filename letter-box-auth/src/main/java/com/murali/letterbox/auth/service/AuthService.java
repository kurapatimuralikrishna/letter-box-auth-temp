package com.murali.letterbox.auth.service;

import javax.validation.Valid;

import org.springframework.http.ResponseEntity;

import com.murali.letterbox.auth.payload.request.LoginRequest;
import com.murali.letterbox.auth.payload.request.SignupRequest;

public interface AuthService {

	ResponseEntity<?> authenticateUser(@Valid LoginRequest loginRequest);

	ResponseEntity<?> registerUser(@Valid SignupRequest signup);

	ResponseEntity<?> logoutUser();

}
