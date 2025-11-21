package com.clipers.clipers.config;

import com.clipers.clipers.security.CustomUserDetailsService;
import com.clipers.clipers.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final Environment environment;

    @Value("${cors.allowed.origins}")
    private String[] allowedOrigins;

    @Autowired
    public SecurityConfig(CustomUserDetailsService customUserDetailsService,
                         JwtAuthenticationFilter jwtAuthenticationFilter,
                         Environment environment) {
        this.customUserDetailsService = customUserDetailsService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.environment = environment;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        boolean isDevelopment = Arrays.asList(environment.getActiveProfiles()).contains("dev") 
                             || environment.getActiveProfiles().length == 0; // default profile is dev
        
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
                // Public endpoints - always accessible
                auth.requestMatchers("/api/auth/login").permitAll()
                    .requestMatchers("/api/auth/register").permitAll()
                    .requestMatchers("/api/auth/refresh").permitAll()
                    .requestMatchers("/api/auth/me").authenticated()
                    .requestMatchers("/api/public/**").permitAll()
                    .requestMatchers("/api/clipers/public/**").permitAll()
                    .requestMatchers("/api/jobs/public/**").permitAll()
                    .requestMatchers("/api/posts/public/**").permitAll()
                    .requestMatchers("/api/stream/**").permitAll()
                    .requestMatchers("/api/uploads/**").permitAll()
                    .requestMatchers("/uploads/**").permitAll()
                    .requestMatchers("/actuator/health").permitAll()
                    .requestMatchers("/error").permitAll()
                    .requestMatchers("/").permitAll();
                
                // Development-only endpoints (test & admin cleanup)
                if (isDevelopment) {
                    auth.requestMatchers("/api/test/**").permitAll()
                        .requestMatchers("/api/clipers/admin/clear-all").permitAll()
                        .requestMatchers("/api/clipers/admin/clear-all-data").permitAll()
                        .requestMatchers("/api/posts/cleanup-company-videos").permitAll();
                } else {
                    // In production, these require ADMIN role
                    auth.requestMatchers("/api/test/**").hasRole("ADMIN")
                        .requestMatchers("/api/clipers/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/posts/cleanup-**").hasRole("ADMIN");
                }
                
                // Admin only endpoints
                auth.requestMatchers("/api/admin/**").hasRole("ADMIN")
                    
                    // Company specific endpoints
                    .requestMatchers("/api/jobs/create").hasRole("COMPANY")
                    .requestMatchers("/api/jobs/*/edit").hasRole("COMPANY")
                    .requestMatchers("/api/dashboard/**").hasRole("COMPANY")
                    
                    // Candidate specific endpoints
                    .requestMatchers("/api/clipers/upload").hasRole("CANDIDATE")
                    .requestMatchers("/api/profile/ats").hasRole("CANDIDATE")
                    
                    // All other endpoints require authentication
                    .anyRequest().authenticated();
            });

        // Add JWT filter
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Usar orígenes específicos de la variable de entorno
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        source.registerCorsConfiguration("/uploads/**", configuration);
        return source;
    }
}
