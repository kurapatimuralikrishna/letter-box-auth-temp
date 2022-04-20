package com.murali.letterbox.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.murali.letterbox.auth.service.TestService;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {
	@Autowired
	TestService service;
	@GetMapping("/")
	public String allAccess() {
		return service.allAccess();
	}
	@GetMapping("/user")
	@PreAuthorize("hasRole('USER') or hasRole('MOD') or hasRole('ADMIN')")
	public String userAccess() {
		return service.userAccess();
	}
	@GetMapping("/mod")
	@PreAuthorize("hasRole('MOD')")
	public String modAccess() {
		return service.modAccess();
	}
	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public String adminAccess() {
		return service.adminAccess();
	}
}
