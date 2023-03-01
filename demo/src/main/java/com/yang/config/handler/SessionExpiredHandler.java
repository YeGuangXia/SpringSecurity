package com.yang.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 16:52
 * @Description: session 失效处理器
 */
public class SessionExpiredHandler implements SessionInformationExpiredStrategy {

    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        HttpServletResponse response = event.getResponse();
        response.setContentType("application/json;charset=UTF-8");
        Map<String, Object> result = new HashMap<>();
        result.put("status", 500);
        result.put("msg", "当前会话已经失效,请重新登录!");
        String s = new ObjectMapper().writeValueAsString(result);
        response.getWriter().println(s);
        response.flushBuffer();
    }
}
