package com.yang.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yang.entity.User;
import com.yang.utils.JwtUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 16:49
 * @Description: 登入成功处理器
 */
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        String token = JwtUtil.createToken(authentication.getName());
        HashMap<String, Object> map = new HashMap<>();
        map.put("msg", "登入成功");
        map.put("status", 200);
        map.put("token", token);
        response.setContentType("application/json;charset=UTF-8");
        String json = new ObjectMapper().writeValueAsString(map);

        response.getWriter().println(json);
    }
}
