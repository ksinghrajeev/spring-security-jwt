package com.rajeev.springjwt.payload;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("refresh_token")
    private String refreshToken;

    private String message;

    /** If you want, you can add these attributes with Response
     * private String token;
     * private String type = "Bearer";
     * private Long id;
     * private String username;
     * private String email;
     * private List<String> roles;
    **/
}
