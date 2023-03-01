package com.yang.config.filter;

import com.yang.entity.User;
import com.yang.service.UserService;
import com.yang.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * @Author: chenyang
 * @DateTime: 2023/3/1 9:55
 * @Description:
 */
@Component
@Order(-1)
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwtToken = request.getHeader(JwtUtil.HEAD);
        if (Objects.isNull(jwtToken)){
            filterChain.doFilter(request, response);
            return;
        }
        Claims claim = JwtUtil.getTokenClaim(jwtToken);
        if (Objects.isNull(claim)){
            throw new RuntimeException("token 解析失败");
        }
        Boolean expireFlag = JwtUtil.checkClaimExpire(claim);
        if (expireFlag){
            throw new RuntimeException("token 已失效");
        }
        String username = claim.getSubject();
        User user = userService.loadUserByUsername(username);
        if (Objects.isNull(user)){
            throw new RuntimeException("用户信息失效");
        }
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(token);
        filterChain.doFilter(request, response);
    }
}
