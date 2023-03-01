package com.yang.config;

import com.yang.config.handler.LoginFailureHandler;
import com.yang.config.handler.LoginSuccessHandler;
import com.yang.config.handler.LogoutHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/27 13:32
 * @Description:
 */
@Configuration
public class SecurityWebConfig {

    private final UserDetailService userDetailService;

    public SecurityWebConfig(UserDetailService userDetailService) {
        this.userDetailService = userDetailService;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .mvcMatchers("/index")
                .permitAll()
                .anyRequest().authenticated()
                .and().formLogin()
                .successHandler(new LoginSuccessHandler())
                .failureHandler(new LoginFailureHandler())
                .and().logout().logoutSuccessHandler(new LogoutHandler()) // 注销登入处理器
                .and().userDetailsService(userDetailService); // 自定义数据源
        return http.csrf().disable().build();
    }
}
