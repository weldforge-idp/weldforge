package tech.cwvermaak.weldforge.model.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Self-registration. The constraints only refuse what already failed before
 * validation was enforced (B-API-2) -- a missing name reached the database
 * as a 500 -- plus an email that is not an email. Password strength stays
 * with {@code PasswordPolicyService}, which explains its reasons.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequestDto {
    /** Display name; also the username. */
    @NotBlank
    @Size(max = 255)
    private String name;

    @NotBlank
    @Email
    @Size(max = 320)
    private String email;

    @NotBlank
    private String password;
}
