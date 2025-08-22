package com.crypto.crypto.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.crypto.crypto.config.SecurityConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter{

    private final SecurityConfig securityConfig;

        private final JWTService jwtService;
        private final UserDetailsService userDetailsService;

        public JwtAuthFilter(JWTService jwtService, UserDetailsService userDetailsService, SecurityConfig securityConfig){
            this.jwtService = jwtService;
            this.userDetailsService = userDetailsService;
            this.securityConfig = securityConfig;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
        FilterChain filterChain) throws ServletException, IOException {
        
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null && authHeader.startsWith("Bearer ")){
                String token = authHeader.substring(7);
                if(jwtService.isValid(token)){
                    String username = jwtService.extractUsername(token);

                    var userDetails = userDetailsService.loadUserByUsername(username);

                    var auth = new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            }
            filterChain.doFilter(request, response);
        }
}
