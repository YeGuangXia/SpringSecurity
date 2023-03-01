package com.yang.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.Objects;

/**
 * @Author: chenyang
 * @DateTime: 2023/3/1 9:57
 * @Description:
 */
public class JwtUtil {

    public static final Long EXPIRE = 700L;

    public static final String HEAD = "Authentication";

    public static final String SECRET = "nice_try_secret";


    /**
     * 生成 Token
     *
     * @param username
     * @return
     */
    public static String createToken(String username) {

        Date nowDate = new Date();

        Date expireDate = new Date(nowDate.getTime() + EXPIRE * 1000);

        return Jwts.builder()
                .setHeaderParam("type", "JWT")
                .setSubject(username)
                .setIssuedAt(nowDate)
                .setExpiration(expireDate)
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
    }


    /**
     * 获取token中注册信息
     *
     * @param token
     * @return
     */
    public static Claims getTokenClaim(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            return null;
        }
    }


    /**
     * 校验 Claims 是否 过期
     * @param claim
     * @return
     */
    public static Boolean checkClaimExpire(Claims claim) {
        if (Objects.isNull(claim)) {
            return false;
        }
        Date expiration = claim.getExpiration();
        return expiration.before(new Date());
    }
}
