package com.yang.config;

import com.yang.config.handler.LoginFailureHandler;
import com.yang.config.handler.LoginSuccessHandler;
import com.yang.config.handler.LogoutHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/23 16:31
 * @Description:
 */
@Configuration
public class WebSecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.withUsername("admin").password("{noop}123").roles("ADMIN").build();
        return new InMemoryUserDetailsManager(user);
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
                .and().logout().logoutSuccessHandler(new LogoutHandler())
                .and().userDetailsService(userDetailsService()); // 注销登入处理器
        return http.csrf().disable().build();
    }
}
