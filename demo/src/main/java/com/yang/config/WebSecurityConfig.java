package com.yang.config;

import com.yang.config.filter.LoginFilter;
import com.yang.config.handler.*;
import com.yang.config.service.RememberMeService;
import com.yang.config.service.UserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.UUID;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 16:46
 * @Description:
 */
@Configuration
public class WebSecurityConfig {

    private final UserDetailService userDetailService;

    private final DataSource dataSource;

    public WebSecurityConfig(UserDetailService userDetailService, DataSource dataSource) {
        this.userDetailService = userDetailService;
        this.dataSource = dataSource;
    }

    /**
     * 自定义持久化令牌
     *
     * @return
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
//        jdbcTokenRepository.setCreateTableOnStartup(true);
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }

    @Bean
    public RememberMeServices rememberMeServices() {
        return new RememberMeService(UUID.randomUUID().toString(), userDetailService, persistentTokenRepository());
    }

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
        filter.setRememberMeServices(rememberMeServices());

        return filter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .mvcMatchers("/index", "/captcha").permitAll()
                .anyRequest().authenticated()
                .and().formLogin();

        // 注销处理
        http.logout()
                .logoutSuccessHandler(new LogoutHandler());

        // 记住我处理器
        http.rememberMe()
                .tokenRepository(persistentTokenRepository())
                .userDetailsService(userDetailService);

        // session 管理
        http.sessionManagement()
                .maximumSessions(1)
                .expiredSessionStrategy(new SessionExpiredHandler())
                .sessionRegistry(sessionRegistry())
                .maxSessionsPreventsLogin(false);

        // 授权、认证异常处理
        http.exceptionHandling()
                .authenticationEntryPoint(new UnAuthenticationHandler())
                .accessDeniedHandler(new UnAbleAccessHandler());

        // 将生成 csrf 放入到cookie 中
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
//        http.csrf().disable();

        // 跨域处理方案
        http.cors().configurationSource(configurationSource());

        // 添加自定义过滤器
        http.addFilterBefore(loginFilter(http.getSharedObject(AuthenticationManager.class)), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


    /**
     * 配置 Session 的监听器（注意：如果使用并发 Session 控制，一般都需要配置该监听器）
     * 解决 Session 失效后, SessionRegistry 中 SessionInformation 没有同步失效的问题
     *
     * @return
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    /**
     * 注册 SessionRegistry，该 Bean 用于管理 Session 会话并发控制
     * 默认为 SessionRegistryImpl 实现类
     *
     * @return
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }


    /**
     * 跨域资源配置
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
