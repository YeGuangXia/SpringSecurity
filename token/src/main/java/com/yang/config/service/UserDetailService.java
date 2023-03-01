package com.yang.config.service;

import com.yang.entity.User;
import com.yang.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 16:59
 * @Description:
 */
@Component
public class UserDetailService implements UserDetailsService, UserDetailsPasswordService {

    private final UserService userService;

    @Autowired
    public UserDetailService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userService.loadUserByUsername(username);
    }

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        Integer updateRow = userService.updateUser(user.getUsername(), newPassword);
        if (updateRow == 1){
            ((User) user).setPassword(newPassword);
        }
        return user;
    }
}
