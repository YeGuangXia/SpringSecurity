package com.yang.config;

import com.yang.config.filter.LoginFilter;
import com.yang.config.handler.LoginFailureHandler;
import com.yang.config.handler.LoginSuccessHandler;
import com.yang.config.handler.LogoutHandler;
import com.yang.config.handler.UnAuthenticationHandler;
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
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;
import java.util.UUID;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/27 17:44
 * @Description:
 */
@Configuration
public class WebSecurityConfig {

    private final DataSource dataSource;

    public WebSecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        // 项目启动时创建表。第一次启动后注释掉即可
//        jdbcTokenRepository.setCreateTableOnStartup(true);
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }


    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("admin").password("{noop}123").roles("ADMIN").build();
        return new InMemoryUserDetailsManager(user);
    }


    @Bean
    public RememberMeServices rememberMeServices() {
        return new RememberMeService(UUID.randomUUID().toString(), userDetailsService(), persistentTokenRepository());
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public LoginFilter loginFilter(AuthenticationManager authenticationManager) {
        LoginFilter filter = new LoginFilter();
        filter.setUsernameParameter("username");
        filter.setPasswordParameter("password");
        filter.setFilterProcessesUrl("/doLogin");

        filter.setAuthenticationManager(authenticationManager);
        filter.setRememberMeServices(rememberMeServices());

        filter.setAuthenticationFailureHandler(new LoginFailureHandler());
        filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());

        return filter;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .mvcMatchers("/index").permitAll()
                .anyRequest().authenticated()
                .and().formLogin()
                .and().exceptionHandling().authenticationEntryPoint(new UnAuthenticationHandler())
                .and().logout().logoutSuccessHandler(new LogoutHandler())
                .and().rememberMe()
                .tokenRepository(persistentTokenRepository()) // 配置token持久化仓库
                .userDetailsService(userDetailsService())
                .and().addFilterBefore(loginFilter(http.getSharedObject(AuthenticationManager.class)), UsernamePasswordAuthenticationFilter.class);
        return http.csrf().disable().build();
    }

}
