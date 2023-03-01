package com.yang.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.UUID;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/23 16:47
 * @Description: 登入成功处理器
 */
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        HashMap<String, Object> map = new HashMap<>();
        map.put("msg", "登入成功");
        map.put("status", 200);
        map.put("code", UUID.randomUUID());
        response.setContentType("application/json;charset=UTF-8");
        String json = new ObjectMapper().writeValueAsString(map);
        response.getWriter().println(json);
    }
}
