package com.yang.config;

import com.yang.config.filter.JwtFilter;
import com.yang.config.filter.LoginFilter;
import com.yang.config.handler.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 16:46
 * @Description:
 */
@Configuration
public class WebSecurityConfig {

    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public LoginFilter loginFilter(AuthenticationManager authenticationManager) {
        LoginFilter filter = new LoginFilter();

        filter.setFilterProcessesUrl("/doLogin");

        filter.setUsernameParameter("username");
        filter.setPasswordParameter("password");
        filter.setCaptchaParameter("captcha");

        filter.setAuthenticationManager(authenticationManager);

        filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
        filter.setAuthenticationFailureHandler(new LoginFailureHandler());

        return filter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .mvcMatchers("/index", "/captcha").permitAll()
                .anyRequest().authenticated()
                .and().formLogin();

        // ????????????
        http.logout()
                .logoutSuccessHandler(new LogoutHandler());

        // session ??????
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // ???????????????????????????
        http.exceptionHandling()
                .authenticationEntryPoint(new UnAuthenticationHandler())
                .accessDeniedHandler(new UnAbleAccessHandler());

        // ????????? session??? csrf ?????????
        http.csrf().disable();

        http.headers().frameOptions().disable();

        // ??????????????????
        http.cors().configurationSource(configurationSource());

        // ????????????????????????
        http.addFilterAt(jwtFilter, LoginFilter.class);
        http.addFilterBefore(loginFilter(http.getSharedObject(AuthenticationManager.class)), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


    /**
     * ??????????????????
     *
     * @return
     */
    public CorsConfigurationSource configurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
        corsConfiguration.setAllowedMethods(Arrays.asList("*"));
        corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
        corsConfiguration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
}
