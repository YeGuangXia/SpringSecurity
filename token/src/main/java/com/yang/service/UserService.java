package com.yang.service;

import com.yang.entity.User;

public interface UserService {

    User loadUserByUsername(String username);

    Integer updateUser(String username, String password);
}
