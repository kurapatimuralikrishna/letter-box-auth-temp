package com.murali.letterbox.auth.service.impl;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.murali.letterbox.auth.model.User;
import com.murali.letterbox.auth.model.UserDetailsImpl;
import com.murali.letterbox.auth.repository.UserRepository;
@Service
public class UserDetailsServiceImpl implements UserDetailsService{
	@Autowired
	UserRepository userRepository;

	@Override
	@Transactional
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username)
				.orElseThrow(()->new UsernameNotFoundException("User not found with username: " + username));
		return UserDetailsImpl.build(user);
	}
}
