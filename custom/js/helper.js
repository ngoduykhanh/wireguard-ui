/**
 * wgEscape — minimal unsafe HTML escapes for interpolated text nodes
 */
function wgEscapeHtml(s) {
    if (!s && s !== 0) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/"/g, '&quot;');
}

/** HTML attribute value escape (double-quoted attrs) */
function wgEscapeAttr(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

/** Human-readable bytes from kernel wg counters */
/** Server injects window.WG_T in base shell; fallback for pages without bundle. */
if (typeof window.wgT !== 'function') {
    window.wgT = function (k) {
        try {
            var m = window.WG_T;
            return (m && typeof m[k] === 'string') ? m[k] : k;
        } catch (e) {
            return k;
        }
    };
}

function wgFmtBytes(n) {
    if (n == null || n === '' || isNaN(n) || Number(n) < 0) return '—';
    var v = Number(n);
    if (v < 1024) return v + ' B';
    var u = [' KB', ' MB', ' GB', ' TB'];
    var i = -1;
    do {
        v /= 1024;
        i++;
    } while (v >= 1024 && i < u.length - 1);
    var d = v >= 100 || i === 0 ? 0 : 1;
    return v.toFixed(d) + u[i];
}
window.wgFmtBytes = wgFmtBytes;

/**
 * Backend sets `reauthenticate: true` after actions that invalidate the session (e.g. removing the passkey
 * you used to sign in, or changing your password). Redirects to login and returns true.
 */
window.wgReauthenticateRedirectIfNeeded = function (resp) {
    if (!resp || !resp.reauthenticate) return false;
    var bp =
        typeof window.APP_BASE_PATH !== 'undefined' && window.APP_BASE_PATH !== null
            ? String(window.APP_BASE_PATH)
            : '';
    window.location.assign(bp + '/login');
    return true;
};

/** Refresh traffic in card grid (peer perspective). Supports:
 *  - map format: {pubkey: {rx,tx,connected}} from /api/wg-peer-stats (connected = recent WG handshake)
 *  - range format: {peer_totals:[{public_key,rx_bytes,tx_bytes}]} from /api/wg-traffic-series (RX/TX only)
 */
window.wgApplyPeerTrafficStats = function (stats) {
    stats = stats || {};
    var norm = {};
    var hasVpnFlag = false;
    if (Array.isArray(stats.peer_totals)) {
        stats.peer_totals.forEach(function (p) {
            var pk = String((p && p.public_key) || '');
            if (!pk) return;
            norm[pk] = {
                rx: Number((p && p.rx_bytes) || 0),
                tx: Number((p && p.tx_bytes) || 0),
            };
        });
    } else {
        norm = stats;
        hasVpnFlag = true;
    }
    document.querySelectorAll('#client-list .wg-client-card[data-client-pubkey]').forEach(function (card) {
        var pk = card.getAttribute('data-client-pubkey');
        if (!pk) return;
        var row = norm[pk];
        var rxSpan = card.querySelector('.wg-traffic-val[data-wg-traffic="rx"]');
        var txSpan = card.querySelector('.wg-traffic-val[data-wg-traffic="tx"]');
        if (rxSpan) rxSpan.textContent = row ? wgFmtBytes(row.tx) : '—';
        if (txSpan) txSpan.textContent = row ? wgFmtBytes(row.rx) : '—';

        if (hasVpnFlag && row && typeof row.connected === 'boolean') {
            var enabled = card.getAttribute('data-wg-enabled') === 'true';
            card.setAttribute('data-wg-vpn', row.connected ? '1' : '0');
            var badge = card.querySelector('.wg-cc-badge');
            var t = badge && badge.querySelector('.wg-cc-badge-txt');
            if (badge && t) {
                badge.classList.toggle('wg-cc-badge-off', !enabled || !row.connected);
                badge.classList.toggle('wg-cc-badge-on', enabled && row.connected);
                if (!enabled) {
                    t.textContent = wgT('helper.badge_blocked');
                } else if (row.connected) {
                    t.textContent = wgT('helper.badge_online');
                } else {
                    t.textContent = wgT('helper.badge_disconnected');
                }
            }
        }
    });
};

window.wgTogglePeerCard = function (el) {
    if (!el) return;
    var card = (el.classList && el.classList.contains('wg-client-card'))
        ? el
        : (el.closest && el.closest('.wg-client-card'));
    if (!card) return;
    var was = card.classList.contains('expanded');
    document.querySelectorAll('#client-list .wg-client-card').forEach(function (c) {
        c.classList.remove('expanded');
    });
    if (!was) card.classList.add('expanded');
};

function renderClientList(data, peerTraffic) {
    peerTraffic = peerTraffic || {};
    var bp = typeof window.APP_BASE_PATH !== 'undefined' ? window.APP_BASE_PATH : '';
    if (!data || data.length === 0) return;

    if (data.length > 1) {
        $('#client-list').empty();
    } else if (data.length === 1) {
        var onlyId = data[0].Client.id;
        $('#client_' + onlyId).remove();
    }

    $.each(data, function (index, obj) {
        var c = obj.Client;
        var id = wgEscapeHtml(c.id);
        var qrDisabled = obj.QRCode === '' ? ' disabled' : '';

        var telegramHtml = '';
        if (c.telegram_userid && c.telegram_userid.length > 0) {
            telegramHtml = '<span class="info-box-text" style="display:none"><i class="fas fa-tguserid"></i>' + wgEscapeHtml(c.telegram_userid) + '</span>';
        }

        /** enabled: overlay off so buttons/dropdowns work; disabled: overlay on top */
        var overlayStyle = c.enabled ? 'display:none;pointer-events:none;visibility:hidden;' : '';

        var allocatedBadges = '';
        $.each(c.allocated_ips || [], function (i, ip) {
            allocatedBadges += '<small class="badge badge-secondary">' + wgEscapeHtml(ip) + '</small> ';
        });
        var allowedBadges = '';
        $.each(c.allowed_ips || [], function (i, ip) {
            allowedBadges += '<small class="badge badge-secondary">' + wgEscapeHtml(ip) + '</small> ';
        });

        var subnetRangesString = '';
        if (c.subnet_ranges && c.subnet_ranges.length > 0) {
            subnetRangesString = c.subnet_ranges.join(',');
        }

        var notesHtml = '';
        if (c.additional_notes && c.additional_notes.length > 0) {
            notesHtml = '<span class="info-box-text" style="display:none"><i class="fas fa-additional_notes"></i>' + wgEscapeHtml(String(c.additional_notes).toUpperCase()) + '</span>';
        }

        var ipsJoined = (c.allocated_ips || []).join(', ');

        var globalDnsHint = $('#wg-global-dns').length ? String($('#wg-global-dns').val() || '').trim() : '';
        var dnsTxt;
        if (!c.use_server_dns) {
            dnsTxt = wgT('helper.dns_no_server');
        } else if (globalDnsHint.length > 0) {
            dnsTxt = globalDnsHint;
        } else {
            dnsTxt = wgT('helper.dns_empty_list');
        }
        var dnsCell = '<div class="cff-v" style="color:#EF5350;font-weight:600">' + wgEscapeHtml(dnsTxt) + '</div>';
        var kaSec = $('#wg-global-keepalive-sec').length ? String($('#wg-global-keepalive-sec').val() || '').trim() : '';
        if (!kaSec) kaSec = '25';
        var pkRaw = String(c.public_key || '');
        var peerTr = pkRaw ? peerTraffic[pkRaw] : null;
        var rxLbl = peerTr ? wgFmtBytes(peerTr.tx) : '—';
        var txLbl = peerTr ? wgFmtBytes(peerTr.rx) : '—';
        var telegramFootBtn = '';
        if (c.telegram_userid) {
            telegramFootBtn =
                '<button type="button" class="cc-foot-btn" data-toggle="modal" data-target="#modal_telegram_client"' +
                ' data-clientid="' + id + '" data-clientname="' + wgEscapeHtml(c.name) + '">' +
                '<i class="fab fa-telegram-plane"></i><span>Telegram</span></button>';
        }

        var dnsChipTxt = c.use_server_dns ? wgT('helper.dns_active') : wgT('helper.dns_inactive');

        var vpnConnected = !!(peerTr && peerTr.connected);
        var badgeCls = 'wg-cc-badge-off';
        var badgeTxt = wgT('helper.badge_blocked');
        var vpnAttr = '0';
        if (c.enabled) {
            if (vpnConnected) {
                badgeCls = 'wg-cc-badge-on';
                badgeTxt = wgT('helper.badge_online');
                vpnAttr = '1';
            } else {
                badgeCls = 'wg-cc-badge-off';
                badgeTxt = wgT('helper.badge_disconnected');
                vpnAttr = '0';
            }
        }

        var html = '' +
            '<div class="wg-client-card client-card" id="client_' + id + '"' +
                ' data-wg-vpn="' + vpnAttr + '" data-wg-online="' + vpnAttr + '" data-wg-enabled="' + (c.enabled ? 'true' : 'false') + '"' +
                ' data-client-pubkey="' + wgEscapeAttr(pkRaw) + '">' +
                '<div class="cc-head">' +
                    '<div class="cc-head-top">' +
                        '<div class="cc-head-main">' +
                            '<div class="wg-paused-overlay" id="paused_' + id + '" style="' + overlayStyle + '" title="' + wgEscapeAttr(wgT('helper.client_disabled')) + '">' +
                                '<i class="paused-client fas fa-3x fa-play" onclick="resumeClient(\'' + id + '\')" style="cursor:pointer;color:var(--acc,#EF5350);position:relative;z-index:3" aria-hidden="true"></i>' +
                            '</div>' +
                            '<div class="cc-peer-click" onclick="wgTogglePeerCard(this.closest(\'.wg-client-card\'))">' +
                                '<div class="cc-avatar">' +
                                    '<i class="fas fa-laptop" style="color:#EF5350"></i>' +
                                '</div>' +
                                '<div class="cc-info">' +
                                    '<span class="info-box-text wg-title"><i class="fas fa-user"></i> ' + wgEscapeHtml(c.name) + '</span>' +
                                    '<span class="info-box-text" style="display:none"><i class="fas fa-envelope"></i>' +
                                        wgEscapeHtml(c.email || '') + '</span>' +
                                    '<div class="cc-meta">' + wgEscapeHtml(ipsJoined) + ' · ' + wgEscapeHtml(wgT('helper.updated')) + ' ' + prettyDateTime(c.updated_at) + '</div>' +
                                    '<span class="info-box-text" style="display:none"><i class="fas fa-key"></i>' + wgEscapeHtml(c.public_key || '') + '</span>' +
                                    '<span class="info-box-text" style="display:none"><i class="fas fa-subnetrange"></i>' + wgEscapeHtml(subnetRangesString) + '</span>' +
                                    telegramHtml + notesHtml +
                                '</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="cc-head-right" onclick="event.stopPropagation()">' +
                            '<span class="wg-cc-badge ' + badgeCls + '">' +
                                '<span class="wg-cc-badge-dot" aria-hidden="true"></span>' +
                                '<span class="wg-cc-badge-txt">' + wgEscapeHtml(badgeTxt) + '</span></span>' +
                            '<label class="wg-cc-switch" title="' + wgEscapeAttr(wgT('helper.switch_peer')) + '">' +
                                '<input type="checkbox" class="wg-cc-toggle"' + (c.enabled ? ' checked' : '') +
                                ' data-clientid="' + id + '" onchange="wgPeerToggleEnable(event,this)" onclick="event.stopPropagation()"/>' +
                                '<span class="wg-cc-switch-track" aria-hidden="true"></span>' +
                            '</label>' +
                        '</div>' +
                    '</div>' +
                    '<div class="cc-extra-lines" onclick="event.stopPropagation()" aria-label="' + wgEscapeAttr(wgT('helper.peer_meta_aria')) + '">' +
                        '<span class="cc-chip" title="' + wgEscapeAttr(wgT('helper.email_title')) + '">' +
                            '<i class="fas fa-envelope" aria-hidden="true"></i>' +
                            '<span class="cc-chip-body">' +
                                '<span class="cc-chip-k">' + wgEscapeHtml(wgT('helper.email_short_lbl')) + '</span>' +
                                '<span class="cc-chip-val">' + wgEscapeHtml(c.email || '—') + '</span></span></span>' +
                        '<span class="cc-chip" title="' + wgEscapeAttr(wgT('helper.created_chip_title')) + '">' +
                            '<i class="fas fa-clock" aria-hidden="true"></i>' +
                            '<span class="cc-chip-body">' +
                                '<span class="cc-chip-k">' + wgEscapeHtml(wgT('helper.created_lbl')) + '</span>' +
                                '<span class="cc-chip-dat">' + wgEscapeHtml(prettyDateTime(c.created_at)) + '</span></span></span>' +
                        '<span class="cc-chip" title="' + wgEscapeAttr(wgT('helper.updated_chip_title')) + '">' +
                            '<i class="fas fa-history" aria-hidden="true"></i>' +
                            '<span class="cc-chip-body">' +
                                '<span class="cc-chip-k">' + wgEscapeHtml(wgT('helper.updated_lbl')) + '</span>' +
                                '<span class="cc-chip-dat">' + wgEscapeHtml(prettyDateTime(c.updated_at)) + '</span></span></span>' +
                        '<span class="cc-chip">' +
                            '<i class="fas fa-server' + (c.use_server_dns ? '' : ' text-muted-cc') +
                            '" aria-hidden="true"></i>' +
                            '<span class="cc-chip-body">' +
                                '<span class="cc-chip-k">' + wgEscapeHtml(wgT('helper.dns_section_lbl')) + '</span>' +
                                '<span class="cc-chip-val">' + wgEscapeHtml(dnsChipTxt) + '</span></span></span>' +
                        (c.additional_notes ? '<span class="cc-chip cc-chip-wide"><i class="fas fa-file-alt" aria-hidden="true"></i>' +
                            '<span class="cc-chip-body">' +
                                '<span class="cc-chip-k">' + wgEscapeHtml(wgT('helper.notes_inline_lbl')) + '</span>' +
                                '<span class="cc-chip-val">' + wgEscapeHtml(c.additional_notes) + '</span></span></span>' : '') +
                    '</div>' +
                '</div>' +
                '<div class="cc-body">' +
                    '<div class="cc-body-inner">' +
                        '<div class="cc-grid cc-grid-mock">' +
                            '<div class="cc-field"><div class="cff-k">' + wgEscapeHtml(wgT('helper.field_allocated')) + '</div><div class="cff-v">' + allocatedBadges + '</div></div>' +
                            '<div class="cc-field"><div class="cff-k">' + wgEscapeHtml(wgT('helper.field_dns')) + '</div>' + dnsCell + '</div>' +
                            '<div class="cc-field"><div class="cff-k">' + wgEscapeHtml(wgT('helper.field_allowed')) + '</div><div class="cff-v">' + allowedBadges + '</div></div>' +
                            '<div class="cc-field cc-field-traf"><div class="cff-k">' + wgEscapeHtml(wgT('helper.field_down')) + '</div><div class="cff-v wg-traf-rx"><i class="fas fa-arrow-down"></i> ' +
                                '<span data-wg-traffic="rx" class="wg-traffic-val">' + rxLbl + '</span></div></div>' +
                            '<div class="cc-field cc-field-traf"><div class="cff-k">' + wgEscapeHtml(wgT('helper.field_up')) + '</div><div class="cff-v wg-traf-tx"><i class="fas fa-arrow-up"></i> ' +
                                '<span data-wg-traffic="tx" class="wg-traffic-val">' + txLbl + '</span></div></div>' +
                            '<div class="cc-field"><div class="cff-k">' + wgEscapeHtml(wgT('helper.field_keepalive')) + '</div><div class="cff-v">' + wgEscapeHtml(String(kaSec)) + 's</div></div>' +
                            '<div class="cc-field"><div class="cff-k">' + wgEscapeHtml(wgT('helper.field_extra_allowed')) + '</div><div class="cff-v">' +
                                wgEscapeHtml((c.extra_allowed_ips || []).join(',') || '—') + '</div></div>' +
                            '<div class="cc-field"><div class="cff-k">' + wgEscapeHtml(wgT('helper.field_subnets')) + '</div><div class="cff-v">' + wgEscapeHtml(subnetRangesString || '—') + '</div></div>' +
                            '<div class="cc-field"><div class="cff-k">' + wgEscapeHtml(wgT('helper.field_endpoint')) + '</div><div class="cff-v">' + wgEscapeHtml(c.endpoint || '—') + '</div></div>' +
                        '</div>' +
                        '<div class="cc-pub">' +
                            '<div class="cff-k">' + wgEscapeHtml(wgT('helper.peer_pubkey')) + '</div>' +
                            '<div class="cc-pub-val" translate="no">' + wgEscapeHtml(c.public_key || '') + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="cc-foot">' +
                        '<div class="cc-foot-left">' +
                            '<button type="button" class="cc-foot-btn"' + qrDisabled +
                            ' data-toggle="modal"' +
                            ' data-target="#modal_qr_client"' +
                            ' data-clientid="' + id + '"' +
                            ' data-clientname="' + wgEscapeHtml(c.name) + '">' +
                            '<i class="fas fa-qrcode"></i><span>' + wgEscapeHtml(wgT('helper.btn_qr')) + '</span></button>' +
                            '<a class="cc-foot-btn cc-foot-download" href="' + bp + '/download?clientid=' + id + '">' +
                            '<i class="fas fa-download"></i><span>' + wgEscapeHtml(wgT('helper.btn_dl')) + '</span></a>' +
                            '<button type="button" class="cc-foot-btn"' +
                            ' data-toggle="modal"' +
                            ' data-target="#modal_edit_client"' +
                            ' data-clientid="' + id + '"' +
                            ' data-clientname="' + wgEscapeHtml(c.name) + '">' +
                            '<i class="fas fa-edit"></i><span>' + wgEscapeHtml(wgT('helper.btn_edit')) + '</span></button>' +
                            '<button type="button" class="cc-foot-btn"' +
                            ' data-toggle="modal"' +
                            ' data-target="#modal_email_client"' +
                            ' data-clientid="' + id + '"' +
                            ' data-clientname="' + wgEscapeHtml(c.name) + '">' +
                            '<i class="fas fa-envelope"></i><span>' + wgEscapeHtml(wgT('helper.email_title')) + '</span></button>' +
                            telegramFootBtn +
                        '</div>' +
                        '<div class="cc-foot-right">' +
                            '<button type="button" class="cc-foot-btn cc-foot-del"' +
                            ' data-toggle="modal"' +
                            ' data-target="#modal_remove_client"' +
                            ' data-clientid="' + id + '"' +
                            ' data-clientname="' + wgEscapeHtml(c.name) + '">' +
                            '<i class="fas fa-trash-alt"></i><span>' + wgEscapeHtml(wgT('helper.btn_del')) + '</span></button>' +
                        '</div>' +
                    '</div>' +
                '</div>' +
            '</div>';

        $('#client-list').append(html);
    });

    $('.wg-client-card:first').addClass('expanded');
}

window.updateSubnetRangesList = function (elementID, preselectedVal) {
    var bp = typeof window.APP_BASE_PATH !== 'undefined' ? window.APP_BASE_PATH : '';
    $.getJSON(bp + '/api/subnet-ranges', null, function (data) {
        $(elementID + ' option').remove();
        $(elementID).append(
            $('<option></option>')
                .text('Any')
                .val('__default_any__')
        );
        $.each(data, function (index, item) {
            $(elementID).append(
                $('<option></option>')
                    .text(item)
                    .val(item)
            );
            if (item === preselectedVal) {
                $(elementID).val(preselectedVal).trigger('change');
            }
        });
    });
};

function prettyDateTime(timeStr) {
    const dt = new Date(timeStr);
    const offsetMs = dt.getTimezoneOffset() * 60 * 1000;
    const dateLocal = new Date(dt.getTime() - offsetMs);
    return dateLocal.toISOString().slice(0, 19).replace(/-/g, '/').replace('T', ' ');
}
