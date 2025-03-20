package com.spotify.repository;

import com.spotify.entity.Role;
import com.spotify.enums.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleEnum name);
    boolean existsByName(RoleEnum name);
}
