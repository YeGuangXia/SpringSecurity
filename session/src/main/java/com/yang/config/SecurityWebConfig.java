package com.yang.config;

import com.yang.handler.SessionExpiredHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 14:05
 * @Description:
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityWebConfig {


    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("admin").password("{noop}111").roles("SUPER_ADMIN").build());
        return manager;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
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
     * 当配置了.maximumSessions(1).maxSessionsPreventsLogin(false)要求只能一个用户 Session 登录时，
     * 我们在两个地方使用相同的账号，并且都勾选 remember-me 进行登录。
     * 最老会话的下一次请求不但会使老会话强制失效，还会使数据库中所有该用户的所有 remember-me 记录被删除
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .mvcMatchers("/index").permitAll()
                .mvcMatchers("/hello").authenticated()
                .and().formLogin();

        http.rememberMe();

        // session 管理
        http.sessionManagement() // 开启会话管理
                .maximumSessions(1) // 允许同一个用户只允许创建一个会话
                .expiredSessionStrategy(new SessionExpiredHandler()) // session 失效处理类
                .sessionRegistry(sessionRegistry()) // session 存储策略
                .maxSessionsPreventsLogin(false);// 登录之后禁止再次登录

        // 将生成 csrf 放入到cookie 中
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

        // 跨域处理方案
        http.cors().configurationSource(configurationSource());


        // 异常处理，认证异常和授权异常
        return http.build();
    }

    /**
     * 跨域资源配置
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
