package com.murali.letterbox.auth.service.impl;

import org.springframework.stereotype.Service;

import com.murali.letterbox.auth.service.TestService;

@Service
public class TestServiceImpl implements TestService {
	public String allAccess() {
		return "Public Content";
	}
	public String userAccess() {
		return "User Content";
	}
	public String modAccess() {
		return "Mod Content";
	}
	public String adminAccess() {
		return "Admin Content";
	}
}
