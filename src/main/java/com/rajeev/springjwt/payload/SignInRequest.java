package com.rajeev.springjwt.payload;


import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SignInRequest {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}
