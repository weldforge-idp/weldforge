package tech.cwvermaak.intellisso.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import tech.cwvermaak.intellisso.model.LdapProviderType;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LdapProviderDto {
    private Long id;
    private Long tenantId;
    private String name;
    private LdapProviderType providerType;
    private String url;
    private String bindDn;
    /** Write-only — never echoed on read. */
    private String bindPassword;
    private String userBaseDn;
    private String userSearchFilter;
    private String emailAttribute;
    private String nameAttribute;
    private String usernameAttribute;
    private Boolean startTls;
    private Integer connectTimeoutMs;
    private Integer readTimeoutMs;
    private Boolean enabled;
}
