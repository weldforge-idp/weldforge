package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import tech.cwvermaak.intellisso.model.payment.GatewayProvider;
import tech.cwvermaak.intellisso.model.payment.GatewayScope;
import tech.cwvermaak.intellisso.model.payment.PaymentGateway;

import java.util.List;
import java.util.Optional;

public interface PaymentGatewayRepository extends JpaRepository<PaymentGateway, Long> {

    List<PaymentGateway> findByScopeAndEnabledTrue(GatewayScope scope);

    @Query("""
        select g from PaymentGateway g
        where g.scope = 'PLATFORM' and g.enabled = true
        order by g.priority desc, g.id asc
        """)
    List<PaymentGateway> findEnabledPlatformGateways();

    @Query("""
        select g from PaymentGateway g
        where g.scope = 'TENANT' and g.tenant.id = :tenantId and g.enabled = true
        order by g.priority desc, g.id asc
        """)
    List<PaymentGateway> findEnabledTenantGateways(Long tenantId);

    Optional<PaymentGateway> findByIdAndTenantId(Long id, Long tenantId);

    Optional<PaymentGateway> findFirstByScopeAndProviderAndEnabledTrue(GatewayScope scope, GatewayProvider provider);
}
