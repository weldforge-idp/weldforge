/* ============================================================
   WeldForge order funnel — client wiring.

   Self-serve tiers POST to the backend order endpoint on
   sso.weldforge.org, which creates a pending_orders row, picks the
   cheapest configured gateway, creates a checkout session with it,
   and returns the hosted-checkout URL. We then redirect.

   While BACKEND_ENABLED is false (no live Stripe account + no Pty
   Ltd yet) every self-serve click degrades cleanly to a mailto: so
   no button on the marketing site is ever dead. Flip the flag the
   day Stripe is live.
   ============================================================ */
(function () {
    'use strict';

    /* ---- Config ---------------------------------------------- */

    // Flip to true once the WeldForge (Pty) Ltd Stripe account is
    // live and the sso.weldforge.org backend has a gateway configured.
    var BACKEND_ENABLED = false;

    var API_BASE      = 'https://sso.weldforge.org';
    var OSS_URL       = 'https://github.com/christiaanwvermaak/intelli-sso';
    var SALES_EMAIL   = 'sales@weldforge.org';
    var ORDERS_WEBHOOK = '';

    /* ---- State ---- */
    var selectedTier = null;
    var selectedMode = null;

    /* ---- Helpers ---- */
    function $(id) { return document.getElementById(id); }
    function qsAll(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }

    function getQueryTier() {
        var m = window.location.search.match(/[?&]tier=([a-z0-9-]+)/i);
        return m ? m[1].toLowerCase() : null;
    }

    function showForm(tier, mode) {
        selectedTier = tier;
        selectedMode = mode;
        $('selected-tier').value = tier;
        $('selected-mode').value = mode;

        var formSection = $('form');
        var heading = $('form-heading');
        var lead = $('form-lead');

        qsAll('.self-serve-only').forEach(function (el) {
            el.style.display = mode === 'self-serve' ? '' : 'none';
        });
        qsAll('.sales-only').forEach(function (el) {
            el.style.display = mode === 'sales' ? '' : 'none';
        });

        if (mode === 'self-serve') {
            heading.textContent = 'Your details';
            lead.textContent = 'This information powers your tenant provisioning. You\u2019ll receive your admin credentials, initial service-account token and a link to the admin portal within a few minutes of checkout.';
            $('tenant-slug').required = true;
            $('submit-btn').textContent = 'Continue to checkout';
        } else if (mode === 'sales') {
            heading.textContent = 'Tell us about your deployment';
            lead.textContent = 'We review your requirements, send an onboarding plan and schedule a short call. Typical response time is one business day.';
            $('tenant-slug').required = false;
            $('submit-btn').textContent = 'Send to sales';
        }

        formSection.style.display = '';
        formSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function emailIsBusinessDomain(email) {
        var blocked = [
            'gmail.com', 'googlemail.com',
            'yahoo.com', 'yahoo.co.uk', 'yahoo.co.za',
            'outlook.com', 'hotmail.com', 'live.com',
            'icloud.com', 'me.com',
            'aol.com',
            'proton.me', 'protonmail.com',
            'mail.com', 'gmx.com', 'gmx.net'
        ];
        var at = email.lastIndexOf('@');
        if (at < 0) return false;
        var domain = email.slice(at + 1).toLowerCase();
        return blocked.indexOf(domain) === -1;
    }

    function buildMailtoFallback(tier, payload) {
        var subject = encodeURIComponent('[Order \u2014 ' + tier + '] ' + (payload.organisation || 'New enquiry'));
        var body = encodeURIComponent(
            'Tier:  ' + tier + '\n' +
            'Mode:  ' + selectedMode + '\n\n' +
            'Organisation:  ' + (payload.organisation || '') + '\n' +
            'Contact:       ' + (payload.contactName || '') + ' <' + (payload.contactEmail || '') + '>\n' +
            'Tenant slug:   ' + (payload.tenantSlug || '(not provided)') + '\n' +
            'Region:        ' + (payload.region || '(not provided)') + '\n' +
            'Billing cycle: ' + (payload.billingCycle || '(not provided)') + '\n' +
            'MAU estimate:  ' + (payload.mauEstimate || '(not provided)') + '\n\n' +
            'Compliance / notes:\n' + (payload.complianceNotes || '(none)') + '\n'
        );
        return 'mailto:' + SALES_EMAIL + '?subject=' + subject + '&body=' + body;
    }

    function postOrderToBackend(payload) {
        // Shape matches CreateOrderRequest in the Spring Boot backend.
        // billingCountry defaults to ZA — refinement once we add a
        // country selector to the form.
        var body = {
            tier:           payload.tier,
            organisation:   payload.organisation,
            contactName:    payload.contactName,
            contactEmail:   payload.contactEmail,
            tenantSlug:     payload.tenantSlug,
            region:         payload.region || null,
            billingCycle:   payload.billingCycle || 'MONTHLY',
            currency:       'USD',
            billingCountry: 'ZA',
            termsAccepted:  payload.termsAccepted
        };
        return fetch(API_BASE + '/api/public/orders', {
            method: 'POST',
            mode: 'cors',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        }).then(function (resp) {
            if (!resp.ok) {
                return resp.json()
                    .catch(function () { return { message: 'order failed (HTTP ' + resp.status + ')' }; })
                    .then(function (err) {
                        throw new Error(err.message || 'order failed (HTTP ' + resp.status + ')');
                    });
            }
            return resp.json();
        });
    }

    function redirectToCheckout(tier, payload) {
        if (!BACKEND_ENABLED) {
            // Backend not yet wired — degrade to mailto so no button
            // on the site is dead while we finish business setup.
            window.location.href = buildMailtoFallback(tier, payload);
            return;
        }
        $('submit-btn').disabled = true;
        $('submit-btn').textContent = 'Creating your order\u2026';
        postOrderToBackend(payload)
            .then(function (resp) {
                if (resp && resp.checkoutUrl) {
                    window.location.href = resp.checkoutUrl;
                } else {
                    throw new Error('backend did not return a checkout URL');
                }
            })
            .catch(function (e) {
                $('submit-btn').disabled = false;
                $('submit-btn').textContent = 'Continue to checkout';
                var banner = document.createElement('div');
                banner.className = 'field-error';
                banner.textContent = 'Sorry — ' + (e.message || 'could not start checkout') +
                    '. Falling back to email us directly\u2026';
                $('order-form').prepend(banner);
                setTimeout(function () {
                    window.location.href = buildMailtoFallback(tier, payload);
                }, 1500);
            });
    }

    /* ---- Tier-select click ---- */
    qsAll('.tier-option').forEach(function (card) {
        card.addEventListener('click', function (ev) {
            var tier = card.getAttribute('data-tier');
            var mode = card.getAttribute('data-mode');

            if (mode === 'opensource') {
                window.location.href = OSS_URL;
                return;
            }
            qsAll('.tier-option').forEach(function (c) { c.classList.remove('selected'); });
            card.classList.add('selected');
            showForm(tier, mode);
        });
    });

    /* ---- Form submit ---- */
    $('order-form').addEventListener('submit', function (ev) {
        ev.preventDefault();

        var form = ev.target;
        var payload = {
            tier:             selectedTier,
            mode:             selectedMode,
            organisation:     form.organisation.value.trim(),
            contactName:      form.contactName.value.trim(),
            contactEmail:     form.contactEmail.value.trim(),
            tenantSlug:       form.tenantSlug.value.trim(),
            region:           form.region.value,
            billingCycle:     form.billingCycle.value,
            mauEstimate:      form.mauEstimate.value.trim(),
            complianceNotes:  form.complianceNotes.value.trim(),
            termsAccepted:    form.termsAccepted.checked
        };

        var errs = [];
        if (!payload.organisation) errs.push('organisation');
        if (!payload.contactName)  errs.push('contactName');
        if (!payload.contactEmail) errs.push('contactEmail');
        if (!payload.termsAccepted) errs.push('termsAccepted');

        $('email-error').textContent = '';
        $('slug-error').textContent = '';

        if (payload.contactEmail && !emailIsBusinessDomain(payload.contactEmail)) {
            $('email-error').textContent = 'Please use a work email on your own domain \u2014 generic mailbox providers are not accepted.';
            errs.push('contactEmail');
        }
        if (selectedMode === 'self-serve') {
            if (!payload.tenantSlug) errs.push('tenantSlug');
            if (payload.tenantSlug && !/^[a-z0-9-]+$/.test(payload.tenantSlug)) {
                $('slug-error').textContent = 'Only lowercase letters, digits and hyphens.';
                errs.push('tenantSlug');
            }
        }
        if (errs.length) return;

        if (ORDERS_WEBHOOK) {
            try {
                fetch(ORDERS_WEBHOOK, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                    mode: 'no-cors'
                });
            } catch (e) { /* non-fatal */ }
        }

        if (selectedMode === 'self-serve') {
            redirectToCheckout(selectedTier, payload);
        } else if (selectedMode === 'sales') {
            window.location.href = buildMailtoFallback(selectedTier, payload);
        }
    });

    $('back-btn').addEventListener('click', function () {
        $('form').style.display = 'none';
        $('selector').scrollIntoView({ behavior: 'smooth' });
    });

    /* ---- Pre-select tier from ?tier=... ---- */
    var preTier = getQueryTier();
    if (preTier) {
        var card = document.querySelector('[data-tier="' + preTier + '"]');
        if (card) {
            var prefillNote = $('tier-prefilled');
            if (prefillNote) prefillNote.style.display = '';
            if (card.getAttribute('data-mode') === 'self-serve') {
                card.classList.add('selected');
                showForm(preTier, 'self-serve');
            } else {
                card.classList.add('highlighted');
                card.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    }
})();
