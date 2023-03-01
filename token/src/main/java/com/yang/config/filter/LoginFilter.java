package com.yang.config.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yang.config.exception.CaptchaNotMatchException;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.util.ObjectUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 16:54
 * @Description:
 */
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    public static final String FORM_CAPTCHA_KEY = "captcha";

    private String captchaParameter = FORM_CAPTCHA_KEY;

    public String getCaptchaParameter() {
        return captchaParameter;
    }

    public void setCaptchaParameter(String captchaParameter) {
        this.captchaParameter = captchaParameter;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("========================================");

        if (!request.getMethod().equals("POST")){
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        if (request.getContentType().equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE)){
            Map<String, String> userInfo = null;
            try {
                userInfo = new ObjectMapper().readValue(request.getInputStream(), Map.class);
            } catch (IOException e) {
                e.printStackTrace();
            }

            if (Objects.isNull(userInfo)){
                throw new NullPointerException("登入参数为空！登入失败");
            }

            String username = userInfo.get(getUsernameParameter());
            String password = userInfo.get(getPasswordParameter());
            String captcha = userInfo.get(getCaptchaParameter());
            String sessionVerifyCode = (String) request.getSession().getAttribute(FORM_CAPTCHA_KEY);

            if (ObjectUtils.isEmpty(captcha) || ObjectUtils.isEmpty(sessionVerifyCode)){
                throw new CaptchaNotMatchException("验证码不能为空!");
            }

            if (!captcha.equalsIgnoreCase(sessionVerifyCode)){
                throw new CaptchaNotMatchException("验证码不匹配!");
            }

            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
            setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
        return super.attemptAuthentication(request, response);
    }
}
