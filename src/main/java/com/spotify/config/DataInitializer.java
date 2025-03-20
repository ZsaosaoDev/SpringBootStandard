package com.spotify.config;

import com.spotify.entity.Role;
import com.spotify.enums.RoleEnum;
import com.spotify.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
public class DataInitializer implements CommandLineRunner {
    private final RoleRepository roleRepository;

    public DataInitializer(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public void run(String... args) {
//        List<RoleEnum> roles = Arrays.asList(RoleEnum.USER, RoleEnum.ADMIN, RoleEnum.ARTIST);
        List<RoleEnum> roles = new ArrayList<>(Arrays.asList(RoleEnum.values()));
        for (RoleEnum roleEnum : roles) {
            if (!roleRepository.existsByName(roleEnum)) {
                Role role = new Role();
                role.setName(roleEnum);
                roleRepository.save(role);
                System.out.println("Created role: " + roleEnum);
            }
        }
    }
}