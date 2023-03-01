package com.yang.config.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 17:02
 * @Description:
 */
public class CaptchaNotMatchException extends AuthenticationException {
    public CaptchaNotMatchException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public CaptchaNotMatchException(String msg) {
        super(msg);
    }
}
