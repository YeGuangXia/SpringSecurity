package com.yang.entity;

import lombok.Data;

import java.io.Serializable;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 16:42
 * @Description:  1 ~ 9 scada
 * 10 ~ 15 内蒙环保监控
 *  16 ~ 17 scm
 */
@Data
public class Role implements Serializable {

    private Integer id;
    private String name;
    private String nameZh;
}