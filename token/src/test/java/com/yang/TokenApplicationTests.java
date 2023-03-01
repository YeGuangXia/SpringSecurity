package com.yang;

import com.yang.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class TokenApplicationTests {

    @Test
    void contextLoads() {

        String token = "eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFM1MTIifQ.eyJzdWIiOiJyb290IiwiaWF0IjoxNjc3NjQwODY1LCJleHAiOjE2Nzc2NDE1NjV9.Kb4ExwtQJpSjFkak4wmKzNmpO_NNhT6H9QoSWN6C2Dw5mi_m1lP3iymoKd4D02akrIKbATMH1NYATD4WJk72aw";
        Claims body = Jwts.parser()
                .setSigningKey(JwtUtil.SECRET)
                .parseClaimsJws(token)
                .getBody();
        System.out.println(body);
    }

}
