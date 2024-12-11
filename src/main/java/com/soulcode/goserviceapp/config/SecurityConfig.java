package com.soulcode.goserviceapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final String[] PUBLIC_ROUTES = {
        "/", 
        "/home", 
        "/auth/**", 
        "/css/**", 
        "/js/**", 
        "/assets/**", 
        "/api/**",
        // Rotas do Swagger
        "/v3/api-docs/**",
        "/swagger-ui/**",
        "/swagger-ui.html",
        "/swagger-resources/**",
        "/webjars/**"
    };

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    "/v3/api-docs/**",
                    "/swagger-ui/**", 
                    "/swagger-ui.html",
                    "/swagger-resources/**",
                    "/webjars/**"
                )
            )
            .authorizeRequests()
                .requestMatchers(PUBLIC_ROUTES).permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/prestador/**").hasRole("PRESTADOR")
                .requestMatchers("/cliente/**").hasRole("CLIENTE")
                .anyRequest().authenticated()
            .and()
                .formLogin()
                .loginPage("/auth/login")
                .defaultSuccessUrl("/")
                // Adicione esta linha para remover a exigência de autenticação para rotas do Swagger
                .permitAll();

        return http.build();
    }
}