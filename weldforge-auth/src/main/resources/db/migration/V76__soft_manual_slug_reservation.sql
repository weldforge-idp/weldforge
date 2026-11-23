-- B-PROV-2: a 72-hour anonymous slug reservation invited squatting.
--
-- When no payment gateway is configured, createOrder records the order and
-- held the requested slug for 72 hours on an anonymous, unverified request —
-- long enough, and renewable every three days, to park a desirable slug
-- (a competitor's name, "acme") at no cost, because the contact email is never
-- verified. The hold was a HARD one: the partial unique index below covered
-- every CREATED row, so a second caller asking for the same slug was refused.
--
-- The fix makes the manual-follow-up hold SOFT — the order still records the
-- requested slug as a preference and sales still follows up, but it no longer
-- blocks anyone else, so there is nothing to squat. A card checkout keeps its
-- hard hold: those rows carry a selected_gateway_id (set before the row is
-- flushed) and reach CHECKOUT_STARTED, so they stay in the index. Only the
-- gateway-less CREATED row — the manual path — leaves it.
DROP INDEX pending_orders_active_slug_reservation;

CREATE UNIQUE INDEX pending_orders_active_slug_reservation
    ON pending_orders (requested_tenant_slug)
    WHERE requested_tenant_slug IS NOT NULL
      AND (
        status IN ('CHECKOUT_STARTED', 'PAID', 'PROVISIONING_FAILED')
        OR (status = 'CREATED' AND selected_gateway_id IS NOT NULL)
      );
