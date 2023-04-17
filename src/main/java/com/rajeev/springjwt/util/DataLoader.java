package com.rajeev.springjwt.util;

import com.rajeev.springjwt.models.ERole;
import com.rajeev.springjwt.models.Role;
import com.rajeev.springjwt.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataLoader implements CommandLineRunner {
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        Role role1 = new Role();
        role1.setName(ERole.ROLE_USER);

        Role role2 = new Role();
        role2.setName(ERole.ROLE_ADMIN);

        Role role3 = new Role();
        role3.setName(ERole.ROLE_MODERATOR);

        roleRepository.save(role1);
        roleRepository.save(role2);
        roleRepository.save(role3);
    }
}
