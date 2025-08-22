package com.crypto.crypto.security;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.crypto.crypto.repository.UserRepository;

import org.springframework.security.core.userdetails.UserDetails;

@Service
public class JpaUserDetailsService implements UserDetailsService{
      private final UserRepository userRepository;

      public JpaUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
      }

      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        var user = userRepository.findByUsername(username)
        .orElseThrow(()-> new UsernameNotFoundException("User not found"));

        return org.springframework.security.core.userdetails.User
        .withUsername(user.getUsername())
        .password(user.getPassword())
        .roles("USER")
        .build();
      }
}
