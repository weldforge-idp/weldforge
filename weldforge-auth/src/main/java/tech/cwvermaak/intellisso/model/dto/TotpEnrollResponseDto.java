package tech.cwvermaak.intellisso.model.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TotpEnrollResponseDto {
    private Long factorId;
    /** Base32-encoded shared secret — shown to the user so they can key it in manually. */
    private String secret;
    /** {@code data:image/png;base64,...} QR data URI ready to embed in an img tag. */
    private String qrDataUri;
}
