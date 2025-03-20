package com.spotify.entity;

import jakarta.persistence.*;
import com.spotify.enums.RoleEnum;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "roles")

public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(unique = true)
    private RoleEnum name; // RoleEnum: ADMIN, USER, MODERATOR, ...


}
