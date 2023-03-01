package com.yang.entity;

import lombok.Data;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * @Author: chenyang
 * @DateTime: 2023/2/28 15:11
 * @Description:
 */
@Data
public class CheckCode implements Serializable {

    private String code;

    private LocalDateTime expireTime;
}
