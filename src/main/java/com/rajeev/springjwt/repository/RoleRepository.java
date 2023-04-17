package com.rajeev.springjwt.repository;

import com.rajeev.springjwt.models.ERole;
import com.rajeev.springjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}
