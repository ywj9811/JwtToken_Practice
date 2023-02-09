package com.example.jwt.domain.dto;

import com.example.jwt.domain.Profile;
import lombok.Data;

@Data
public class ProfileDto {
    public static Profile dtoToDomain(String username, String password, String roles) {
        return Profile.builder()
                .username(username)
                .password(password)
                .roles(roles)
                .build();
    }
}
