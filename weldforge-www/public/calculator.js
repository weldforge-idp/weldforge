/* ============================================================
   WeldForge IdP cost calculator — pure client-side, no deps.

   Pricing data is the vendors' own list prices, re-checked
   2026-09-14 against each vendor's public pricing page. Each
   vendor has a price(mau) function returning the monthly bill at
   that volume.

   KEEP THIS IN STEP WITH /compare/*.html. Those pages and this
   calculator quote the same vendors, and on 2026-09-14 they had
   drifted apart — the tables had been corrected while these
   functions still modelled Auth0 as $240/mo from 1k MAU and Clerk
   as free only to 10k. A visitor who read both saw the site
   contradict itself on price, which is worse than either number
   being merely old.

   URL state: ?mau=25000&cycle=annual is kept in sync with the
   controls so the page is shareable.
   ============================================================ */
(function () {
    'use strict';

    // ---- Vendor pricing models (monthly USD, list price) --------

    function weldforge(mau, cycle) {
        // Cheapest tier that covers the volume -- which is what a customer
        // actually buys, and what /compare/*.html already assumes.
        //
        // The previous model escalated from Cloud Team with overage forever,
        // so at 50 000 MAU it quoted $1 149 when Cloud Business covers that
        // volume for $699. It was overcharging us against our own pricing
        // page, and disagreeing with the comparison tables.
        //
        // Tiers from /pricing.html; keep them in step.
        var TIERS = [
            { name: 'Cloud Starter',  base: 0,    included: 500,     over: 0     },
            { name: 'Cloud Starter',  base: 29,   included: 1000,    over: 0     },
            { name: 'Cloud Team',     base: 149,  included: 10000,   over: 0.025 },
            { name: 'Cloud Business', base: 699,  included: 50000,   over: 0.020 },
            { name: 'Cloud Scale',    base: 2499, included: 250000,  over: 0.012 }
        ];

        var best = null;
        for (var i = 0; i < TIERS.length; i++) {
            var t = TIERS[i];
            // A tier can serve any volume; past its allowance it bills overage.
            // Below its allowance there is no discount, so the cost is the base.
            // Starter has no overage rate, so it cannot serve beyond its cap.
            if (mau > t.included && t.over === 0) { continue; }
            var cost = t.base + Math.max(0, mau - t.included) * t.over;
            if (best === null || cost < best) { best = cost; }
        }

        // Annual is the headline; monthly billing carries a 20% surcharge.
        return cycle === 'monthly' ? best * 1.2 : best;
    }

    function auth0(mau /*, cycle */) {
        // B2C line. The free tier now reaches 25 000 MAU -- it used to be a
        // small fraction of that, and modelling the old shape overstated
        // Auth0's cost by hundreds of dollars a month at volumes where they
        // actually charge nothing.
        //
        // Past the free cap, B2C Essentials starts at $35/mo and B2C
        // Professional at $240/mo, both quoted from 500 MAU with tiered
        // escalation rather than a published per-MAU rate. The curve above
        // 25k is therefore an estimate; the free line below it is exact.
        //
        // Not modelled here: Auth0's B2B line, which is where they get
        // expensive (Essentials $150/mo, Professional $800/mo, enterprise
        // connections metered). See /compare/auth0.html.
        if (mau <= 25000)  return 0;
        if (mau <= 50000)  return 240;
        return 240 + (mau - 50000) * 0.015;
    }

    function clerk(mau /*, cycle */) {
        // 50 000 included users on every plan, Hobby included -- not the
        // 10 000 this modelled before.
        //
        // Note the unit: Clerk bills monthly RETAINED users (someone who
        // returns at least a day after signing up), not MAU. For an app with
        // many one-visit signups the real bill is lower than this slider
        // suggests, so treating MAU as MRU is the conservative direction.
        //
        // Overage tiers: $0.02 to 100k, $0.018 to 1m.
        if (mau <= 50000)  return 0;
        if (mau <= 100000) return 25 + (mau - 50000) * 0.02;
        return 25 + 50000 * 0.02 + (mau - 100000) * 0.018;
    }

    function fusionauth(mau /*, cycle */) {
        // Indicative only, and flagged as such in the UI. FusionAuth quotes
        // hosted plans through an MAU slider rather than a fixed published
        // list, their plan names have moved, and the figures found on
        // 2026-09-14 disagreed with each other. Rather than print a precise
        // number we cannot stand behind, the shape is kept -- flat tiers,
        // genuinely competitive at scale -- and the reader is pointed at
        // fusionauth.io/pricing. Self-hosted FusionAuth Community is free and
        // unlimited, as is self-hosted WeldForge.
        if (mau <= 10000)   return 125;
        if (mau <= 100000)  return 225;
        return 425;
    }

    var VENDORS = [
        { key: 'weldforge',  name: 'WeldForge',  price: weldforge,  highlight: true },
        { key: 'auth0',      name: 'Auth0',      price: auth0 },
        { key: 'clerk',      name: 'Clerk',      price: clerk },
        { key: 'fusionauth', name: 'FusionAuth', price: fusionauth }
    ];

    // ---- Helpers ------------------------------------------------

    function $(id) { return document.getElementById(id); }
    function fmtUsdMonth(n) {
        if (n === 0) return '$0';
        if (n < 1) return '$' + n.toFixed(2);
        return '$' + Math.round(n).toLocaleString('en-US');
    }
    function fmtUsdYear(n) { return fmtUsdMonth(n * 12); }
    function fmtMau(n)     { return n.toLocaleString('en-US'); }

    // ---- State + URL sync ---------------------------------------

    function readHash() {
        var m = window.location.hash.slice(1).split('&').reduce(function (acc, kv) {
            var ix = kv.indexOf('=');
            if (ix < 0) return acc;
            acc[decodeURIComponent(kv.slice(0, ix))] = decodeURIComponent(kv.slice(ix + 1));
            return acc;
        }, {});
        return {
            mau:   Math.max(100, Math.min(500000, parseInt(m.mau, 10) || 10000)),
            cycle: m.cycle === 'monthly' ? 'monthly' : 'annual'
        };
    }

    function writeHash(state) {
        var next = '#mau=' + state.mau + '&cycle=' + state.cycle;
        if (next !== window.location.hash) {
            window.history.replaceState(null, '', next);
        }
    }

    // ---- Render -------------------------------------------------

    function render(state) {
        $('mau-display').textContent = fmtMau(state.mau) + ' MAU';

        var quotes = VENDORS.map(function (v) {
            return {
                vendor: v,
                monthly: v.price(state.mau, state.cycle)
            };
        });

        // Find the cheapest monthly figure so we can style it.
        var cheapest = quotes.reduce(function (min, q) {
            return q.monthly < min ? q.monthly : min;
        }, Infinity);
        // Highest is used for bar-width scaling.
        var highest = quotes.reduce(function (max, q) {
            return q.monthly > max ? q.monthly : max;
        }, 0);

        var root = $('calc-results');
        root.innerHTML = '';
        quotes.forEach(function (q) {
            var row = document.createElement('div');
            row.className = 'calc-row'
                + (q.vendor.highlight ? ' is-weldforge' : '')
                + (q.monthly === cheapest ? ' is-cheapest' : '');

            var barWidth = highest === 0 ? 0 : Math.max(2, Math.round(q.monthly / highest * 100));

            row.innerHTML =
                '<div class="calc-row-label">' + escapeHtml(q.vendor.name) + '</div>' +
                '<div class="calc-row-bar"><span class="calc-row-bar-fill" style="width:' + barWidth + '%"></span></div>' +
                '<div class="calc-row-monthly">' + fmtUsdMonth(q.monthly) + '<span class="calc-row-unit"> / mo</span></div>' +
                '<div class="calc-row-annual">' + fmtUsdYear(q.monthly) + ' / yr</div>';

            root.appendChild(row);
        });

        // Savings headline vs Auth0, if WeldForge is cheaper.
        var wf  = quotes.find(function (q) { return q.vendor.key === 'weldforge'; });
        var a0  = quotes.find(function (q) { return q.vendor.key === 'auth0'; });
        if (wf && a0 && a0.monthly > wf.monthly) {
            var savingsMonth = a0.monthly - wf.monthly;
            var headline = document.createElement('div');
            headline.className = 'calc-savings';
            headline.innerHTML =
                'Save <strong>' + fmtUsdMonth(savingsMonth) + ' / mo</strong> ' +
                '(<strong>' + fmtUsdYear(savingsMonth) + ' / yr</strong>) vs Auth0 at this volume.';
            root.appendChild(headline);
        }
    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, function (ch) {
            return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[ch];
        });
    }

    // ---- Wire up ------------------------------------------------

    document.addEventListener('DOMContentLoaded', function () {
        var state = readHash();
        var mauInput = $('mau-input');
        mauInput.value = state.mau;

        Array.prototype.forEach.call(document.querySelectorAll('input[name="cycle"]'), function (r) {
            r.checked = r.value === state.cycle;
            r.addEventListener('change', function () {
                state.cycle = r.value;
                writeHash(state);
                render(state);
            });
        });

        mauInput.addEventListener('input', function () {
            state.mau = parseInt(mauInput.value, 10);
            writeHash(state);
            render(state);
        });

        $('copy-link').addEventListener('click', function () {
            var url = window.location.origin + window.location.pathname + window.location.hash;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(url).then(function () {
                    $('copy-feedback').textContent = '\u2714 copied';
                    setTimeout(function () { $('copy-feedback').textContent = ''; }, 2000);
                });
            } else {
                // Fallback — select the URL in a temp input
                var tmp = document.createElement('input');
                tmp.value = url;
                document.body.appendChild(tmp);
                tmp.select();
                document.execCommand('copy');
                document.body.removeChild(tmp);
                $('copy-feedback').textContent = '\u2714 copied';
                setTimeout(function () { $('copy-feedback').textContent = ''; }, 2000);
            }
        });

        render(state);
    });
})();
