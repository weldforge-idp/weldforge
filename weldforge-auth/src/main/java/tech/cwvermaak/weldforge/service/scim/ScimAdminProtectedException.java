package tech.cwvermaak.weldforge.service.scim;

/**
 * A SCIM write was aimed at a privileged account (WF-11).
 *
 * <p>A SCIM bearer key is a tenant's provisioning credential, handed to an
 * upstream directory (Okta, Workday, Entra ID) to mirror its workforce. It is
 * not an administrative credential, and the review raised — the local
 * penetration test then confirmed — that it could deactivate, overwrite or
 * delete a tenant's own super administrator. A directory sync that removes an
 * employee must never be able to lock the tenant out of its console.
 *
 * <p>So a write (PUT, PATCH, DELETE) whose target holds any admin role is
 * refused. Privileged accounts are managed in the admin console, by a human
 * admin, never by the directory connector. Mapped to {@code 403}.
 */
public class ScimAdminProtectedException extends RuntimeException {
    public ScimAdminProtectedException(String message) {
        super(message);
    }
}
