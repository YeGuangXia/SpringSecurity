package com.yang.config;

import com.yang.config.filter.LoginKaptchaFilter;
import com.yang.config.handler.LoginFailureHandler;
import com.yang.config.handler.LoginSuccessHandler;
import com.yang.config.handler.LogoutHandler;
import com.yang.config.handler.UnAuthenticationHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/23 16:31
 * @Description:
 */
@Configuration
public class WebSecurityConfig {

    private final UserDetailService userDetailService;

    public WebSecurityConfig(UserDetailService userDetailService) {
        this.userDetailService = userDetailService;
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public LoginKaptchaFilter loginKaptchaFilter(AuthenticationManager authenticationManager) {
        LoginKaptchaFilter filter = new LoginKaptchaFilter();
        //1.认证 url
        filter.setFilterProcessesUrl("/doLogin");

        //2.认证 接收参数
        filter.setUsernameParameter("username");
        filter.setPasswordParameter("pwd");
        filter.setKaptchaParameter("kaptcha");

        //3.指定认证管理器
        filter.setAuthenticationManager(authenticationManager);

        // 4.指定成功/失败时处理
        filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
        filter.setAuthenticationFailureHandler(new LoginFailureHandler());

        return filter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .mvcMatchers("/index", "/vc.png")
                .permitAll()
                .anyRequest().authenticated()
                .and().formLogin()
                .and().logout().logoutSuccessHandler(new LogoutHandler()) // 注销登入处理器
                .and().exceptionHandling().authenticationEntryPoint(new UnAuthenticationHandler()) // 未认证处理器
                .and().userDetailsService(userDetailService) // 自定义数据源
                .addFilterBefore(loginKaptchaFilter(http.getSharedObject(AuthenticationManager.class)), UsernamePasswordAuthenticationFilter.class); // 自定义过滤器
        return http.csrf().disable().build();
    }
}
