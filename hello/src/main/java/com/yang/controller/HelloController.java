package com.yang.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/23 11:43
 * @Description:
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        new Thread(() -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User user = (User) authentication.getPrincipal();
            System.out.println(user.toString());
        }).start();
        return "hello page success";
    }


    @GetMapping("/index")
    public String index(){
        return "index page";
    }


}
