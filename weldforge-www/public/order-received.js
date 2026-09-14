/* Fills in the order reference on the post-checkout pages.

   The reference arrives in the query string because these pages are static:
   order-success.html is the URL the payment gateway redirects to, and the
   gateway appends the token we handed it when the checkout was created.

   Deliberately no fetch of order state. Someone reaching this page may have
   just paid, and an unauthenticated endpoint that echoes order details back
   for any token in a URL is a lookup oracle for anyone who guesses tokens.
   The reference alone is enough for a human to find the order.

   External file rather than inline, to satisfy the site's script-src 'self'
   CSP. */
(function () {
    'use strict';

    function param(name) {
        var m = window.location.search.match(new RegExp('[?&]' + name + '=([^&]*)'));
        return m ? decodeURIComponent(m[1].replace(/\+/g, ' ')) : '';
    }

    var panel = document.getElementById('order-detail');
    if (!panel) { return; }

    var token   = param('token');
    var slug    = param('slug');
    var tokenEl = document.getElementById('order-token');
    var slugEl  = document.getElementById('order-slug');
    var shown   = false;

    // textContent, never innerHTML: this value comes from the URL bar and is
    // therefore attacker-controlled.
    if (token && tokenEl) { tokenEl.textContent = token; shown = true; }
    if (slug  && slugEl)  { slugEl.textContent  = slug;  shown = true; }

    // Only reveal the panel when there is something in it. An empty "Your
    // reference" box reads as a bug to someone who has just paid.
    if (shown) { panel.hidden = false; }
}());
