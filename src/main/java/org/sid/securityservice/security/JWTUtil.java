package org.sid.securityservice.security;

import java.util.Date;

public class JWTUtil {

    public static final String SECRET = "mySecret1234";
    public static final String AUTH_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final String REFRESH = "/refreshToken";
    public static final String LOGIN = "/login";

    public static Date EXPIRE_ACCESS_TOKEN(){
        return new Date(System.currentTimeMillis()+300000);
    }

    public static Date EXPIRE_REFRESH_TOKEN(){
        return new Date(System.currentTimeMillis()+25920000000L);
    }
}
