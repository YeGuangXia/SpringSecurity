package com.yang.controller;

import com.google.code.kaptcha.Producer;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.util.FastByteArrayOutputStream;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 17:47
 * @Description:
 */
@RestController
public class CaptchaController {

    private final Producer producer;

    public CaptchaController(Producer producer) {
        this.producer = producer;
    }

    @GetMapping("/captcha")
    public String getVerifyCode(HttpSession session) throws IOException {
        //1.生成验证码
        String code = producer.createText();
        session.setAttribute("captcha", code); //可以更换成 redis 实现
        System.out.println(code);
        BufferedImage bi = producer.createImage(code);
        //2.写入内存
        FastByteArrayOutputStream fos = new FastByteArrayOutputStream();
        ImageIO.write(bi, "png", fos);
        //3.生成 base64
        return Base64.encodeBase64String(fos.toByteArray());
    }
}
