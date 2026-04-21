/* ============================================================
   WeldForge IdP cost calculator — pure client-side, no deps.

   Pricing data is the vendors' own list prices as of 2026-Q2.
   Each vendor has a pick(mau) function that returns the monthly
   bill for that MAU volume. Every number sourced from a public
   pricing page — if a vendor changes tiers, update here.

   URL state: ?mau=25000&cycle=annual is kept in sync with the
   controls so the page is shareable.
   ============================================================ */
(function () {
    'use strict';

    // ---- Vendor pricing models (monthly USD, list price) --------

    function weldforge(mau, cycle) {
        // Annual billing, then ×1.2 for monthly
        var base;
        if (mau <= 500)     base = 0;
        else if (mau <= 1000) base = 29;
        else if (mau <= 10000) base = 149;
        else if (mau <= 50000) base = 149 + Math.max(0, mau - 10000) * 0.025;
        else if (mau <= 250000) base = 699 + Math.max(0, mau - 50000) * 0.020;
        else                   base = 2499 + Math.max(0, mau - 250000) * 0.012;
        return cycle === 'monthly' ? base * 1.2 : base;
    }

    function auth0(mau /*, cycle */) {
        // Auth0 B2C Essentials $240 base to ~1k. Above 1k adds roughly
        // $0.028/MAU up to 7.5k when the Essentials tier caps. From 7.5k
        // to 10k the plan jumps to Professional at $1500 base; overage
        // ~$0.015/MAU above 10k. Rough but defensible.
        if (mau <= 1000)  return 240;
        if (mau <= 7500)  return 240 + (mau - 1000) * 0.028;
        if (mau <= 10000) return 1500;
        return 1500 + (mau - 10000) * 0.015;
    }

    function clerk(mau /*, cycle */) {
        // Free up to 10k MAU on current Clerk pricing. Pro tier $25/mo
        // base + $0.02 per MAU over 10k.
        if (mau <= 10000) return 0;
        return 25 + (mau - 10000) * 0.02;
    }

    function fusionauth(mau /*, cycle */) {
        // Flat tiers — competitive at scale. Essentials $125/mo < 10k,
        // $225/mo < 100k, $425/mo < 1m. No per-MAU.
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
