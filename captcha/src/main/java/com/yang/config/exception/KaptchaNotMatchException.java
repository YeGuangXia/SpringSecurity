package com.yang.config.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/27 10:13
 * @Description:
 */
public class KaptchaNotMatchException extends AuthenticationException {

    public KaptchaNotMatchException(String msg) {
        super(msg);
    }

    public KaptchaNotMatchException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
