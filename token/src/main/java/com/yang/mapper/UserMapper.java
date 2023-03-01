package com.yang.mapper;

import com.yang.entity.Role;
import com.yang.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface UserMapper {

    /**
     * 根据用户名查询用户
     *
     * @param username
     * @return
     */
    User loadUserByUsername(String username);

    /**
     * 根据用户id查询角色
     *
     * @param uid
     * @return
     */
    List<Role> getRolesByUid(Integer uid);


    /**
     * 更新密码
     *
     * @param username
     * @param password
     * @return
     */
    Integer updatePassword(@Param("username") String username, @Param("password") String password);
}
