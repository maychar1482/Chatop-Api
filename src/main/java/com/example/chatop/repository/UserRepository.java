package com.example.chatop.repository;


import com.example.chatop.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findById(long id);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);


}