package com.crypto.crypto.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.crypto.crypto.dto.AuthResponse;
import com.crypto.crypto.dto.LoginRequest;
import com.crypto.crypto.security.JWTService;
import org.springframework.web.bind.annotation.PostMapping;



@RestController
@RequestMapping("api/auith")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;

    public AuthController(AuthenticationManager authenticationManager, JWTService jwtService){
        this.authenticationManager = authenticationManager;
        this. jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Validated @RequestBody LoginRequest request){
        try{
            var authToken = new UsernamePasswordAuthenticationToken(request.username(),request.password());
            authenticationManager.authenticate(authToken);
            String token = jwtService.generateToken(request.username());
            return ResponseEntity.ok(new AuthResponse(token));
        }catch (AuthenticationException ex){
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    } 
    
    
}
