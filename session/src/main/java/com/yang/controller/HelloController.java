package com.yang.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 14:27
 * @Description:
 */
@RestController
public class HelloController {

    @GetMapping("/index")
    public String index(){
        return "index page";
    }

    @GetMapping("/hello")
    public String hello(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();
        return "hello page ! " + user.getUsername();
    }

}
