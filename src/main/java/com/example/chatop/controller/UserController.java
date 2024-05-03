package com.example.chatop.controller;


import com.example.chatop.models.User;
import com.example.chatop.payload.request.LoginRequest;
import com.example.chatop.payload.request.SignupRequest;
import com.example.chatop.payload.response.JwtResponse;
import com.example.chatop.payload.response.MessageResponse;
import com.example.chatop.repository.UserRepository;
import com.example.chatop.security.jwt.JwtUtils;
import com.example.chatop.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJacksonValue;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Optional;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")

public class UserController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    HashMap<String,Object> responseMessage = null;
    MappingJacksonValue    jsonResponse    = null;


    public UserController() {
        this.responseMessage = new HashMap<String,Object>();
        this.jsonResponse    = new MappingJacksonValue(null);
    }


    @GetMapping("/users")
    public Iterable<User> getUsers(){
        Iterable<User> listUsers = userRepository.findAll();
        return listUsers;
    }

    @GetMapping("/user/{id}")
    @PreAuthorize("#id == principal.id")
    public ResponseEntity<Object> getUserById(@PathVariable("id") long id){
        Optional<User> user = this.userRepository.findById(id);

        if (user.isPresent()) {
            return new ResponseEntity<>(user.get(), HttpStatus.OK);
        } else {
            this.responseMessage.put("message","Utilisateur introuvable");
            this.responseMessage.put("status", 404);

            this.jsonResponse.setValue(this.responseMessage);
            return new ResponseEntity<Object>(this.jsonResponse, HttpStatus.NOT_FOUND);
        }

    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest){

        // Verify if email address exist
        boolean isExist = this.userRepository.existsByEmail(loginRequest.getEmail());
        if (!isExist) {
            this.responseMessage.put("Error","Email or Password  incorrect!");
            this.responseMessage.put("status", 401);

            this.jsonResponse.setValue(this.responseMessage);
            return new ResponseEntity<Object>(this.jsonResponse, HttpStatus.UNAUTHORIZED);
        }
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail()));

    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Email is already used!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
