package com.yang.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/27 17:49
 * @Description:
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User principal = (User) authentication.getPrincipal();
        System.out.println(principal.getUsername());
        return "hello page";
    }

    @GetMapping("/index")
    public String index(){
        return "index page";
    }
}
