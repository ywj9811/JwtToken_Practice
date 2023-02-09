package com.example.jwt.respository;

import com.example.jwt.domain.Profile;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProfileRepo extends JpaRepository<Profile, Integer> {
    Profile findByUsername(String username);

    Boolean existsByUsername(String username);
}
