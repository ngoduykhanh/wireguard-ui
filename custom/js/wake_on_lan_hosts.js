var base_url = jQuery(".brand-link").attr('href');
if (base_url.substring(base_url.length - 1, base_url.length) != "/")
    base_url = base_url + "/";


const wake_on_lan_new_template = '<div class="col-sm-4" id="{{ .Id }}">\n' +
    '\t<div class="info-box">\n' +
    '\t\t<div class="info-box-content">\n' +
    '\t\t\t<div class="btn-group">\n' +
    '\t\t\t\t<button type="button" class="btn btn-outline-success btn-sm"\n' +
    '\t\t\t\t\t\tdata-mac-address="{{ .MacAddress }}">Wake On\n' +
    '\t\t\t\t</button>\n' +
    '\t\t\t\t<button type="button"\n' +
    '\t\t\t\t\t\tclass="btn btn-outline-primary btn-sm btn_modify_wake_on_lan_host"\n' +
    '\t\t\t\t\t\tdata-toggle="modal" data-target="#modal_wake_on_lan_host"\n' +
    '\t\t\t\t\t\tdata-name="{{ .Name }}" data-mac-address="{{ .MacAddress }}">Edit\n' +
    '\t\t\t\t</button>\n' +
    '\t\t\t\t<button type="button" class="btn btn-outline-danger btn-sm" data-toggle="modal"\n' +
    '\t\t\t\t\t\tdata-target="#modal_remove_wake_on_lan_host"\n' +
    '\t\t\t\t\t\tdata-mac-address="{{ .MacAddress }}">Remove\n' +
    '\t\t\t\t</button>\n' +
    '\t\t\t</div>\n' +
    '\t\t\t<hr>\n' +
    '\t\t\t<span class="info-box-text"><i class="fas fa-address-card"></i> <span class="name">{{ .Name }}</span></span>\n' +
    '\t\t\t<span class="info-box-text"><i class="fas fa-ethernet"></i> <span class="mac-address">{{ .MacAddress }}</span></span>\n' +
    '\t\t\t<span class="info-box-text"><i class="fas fa-clock"></i> <span class="latest-used">Unused</span></span>\n' +
    '\t\t</div>\n' +
    '\t</div>\n' +
    '</div>';

jQuery(function ($) {
    $.validator.addMethod('mac', function (value, element) {
        return this.optional(element) || /^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$/.test(value);
    }, 'Please enter a valid MAC Address.(uppercase letters and numbers, : only) ex: 00:AB:12:EF:DD:AA');
});

jQuery.each(["put", "delete"], function (i, method) {
    jQuery[method] = function (url, data, callback, type) {
        if (jQuery.isFunction(data)) {
            type = type || callback;
            callback = data;
            data = undefined;
        }

        return jQuery.ajax({
            url: url,
            type: method,
            dataType: type,
            data: data,
            success: callback,
            contentType: 'application/json'
        });
    };
});

jQuery(function ($) {
    let newHostHtml = '<div class="col-sm-2 offset-md-4" style=" text-align: right;"><button style="" id="btn_new_wake_on_lan_host" type="button" class="btn btn-outline-primary btn-sm" data-toggle="modal" data-target="#modal_wake_on_lan_host"><i class="nav-icon fas fa-plus"></i> New Host</button></div>';
    $('h1').parents(".row").append(newHostHtml);
});

jQuery(function ($) {
    $('.btn-outline-success').click(function () {
        const $this = $(this);
        $.put(base_url + 'wake_on_lan_host/' + $this.data('mac-address'), function (result) {
            $this.parents('.info-box').find('.latest-used').text(prettyDateTime(result));
        });
    });
});

jQuery(function ($) {
    let $modal_remove_wake_on_lan_host = $('#modal_remove_wake_on_lan_host');
    let $remove_client_confirm = $('#remove_wake_on_host_confirm');

    $modal_remove_wake_on_lan_host.on('show.bs.modal', function (event) {
        const $btn = $(event.relatedTarget);
        const $modal = $(this);

        const $editBtn = $btn.parents('.btn-group').find('.btn_modify_wake_on_lan_host');
        $modal.find('.modal-body').text("You are about to remove Wake On Lan Host " + $editBtn.data('name'));
        $remove_client_confirm.val($editBtn.data('mac-address'));
    })

    $remove_client_confirm.click(function () {
        const macAddress = $remove_client_confirm.val().replaceAll(":", "-");
        $.delete(base_url + 'wake_on_lan_host/' + macAddress);
        $('#' + macAddress).remove();

        $modal_remove_wake_on_lan_host.modal('hide');
    });
});

jQuery(function ($) {
    $('.latest-used').each(function () {
        const $this = $(this);
        const timeText = $this.text().trim();
        try {
            if (timeText != "Unused") {
                $this.text(prettyDateTime(timeText));
            }
        } catch (ex) {
            console.log(timeText);
            throw ex;
        }
    });
});

jQuery(function ($) {
    let $modal_wake_on_lan_host = $("#modal_wake_on_lan_host");
    let $name = $('#frm_wake_on_lan_host_name');
    let $macAddress = $('#frm_wake_on_lan_host_mac_address');
    let $oldMacAddress = $('#frm_wake_on_lan_host_old_mac_address');
    let $contentRow = $('.content .row');
    let $frm_wake_on_lan_host = $("#frm_wake_on_lan_host");

    // https://jqueryvalidation.org/
    let validator = $frm_wake_on_lan_host.validate({
        submitHandler: function () {
            let data = {
                name: $name.val(),
                mac_address: $macAddress.val().toUpperCase(),
                old_mac_address: $oldMacAddress.val().toUpperCase()
            };
            $.ajax({
                cache: false,
                method: 'POST',
                url: base_url + 'wake_on_lan_host',
                dataType: 'json',
                contentType: "application/json",
                data: JSON.stringify(data),
                success: function (response) {
                    /** @type {string} */
                    let oldMacAddress = $oldMacAddress.val().toUpperCase();

                    if (oldMacAddress != '') {
                        let macAddress = response.MacAddress;
                        let name = response.Name;

                        let $container = $('#' + oldMacAddress.replaceAll(":", "-"));
                        if (macAddress != oldMacAddress) {
                            $container.attr('id', macAddress.replaceAll(":", "-"));
                            $container.find('.mac-address').text(macAddress);
                            $container.find('[data-mac-address]').data('mac-address', macAddress);
                        }

                        $container.find('.name').text(name);
                        $container.find('[data-name]').data('name', name);
                    } else {
                        const $template = $(
                            wake_on_lan_new_template
                                .replace(/{{ .Id }}/g, response.MacAddress.replaceAll(":", "-").toUpperCase())
                                .replace(/{{ .MacAddress }}/g, response.MacAddress.toUpperCase())
                                .replace(/{{ .Name }}/g, response.Name)
                        );

                        $contentRow.append($template);
                    }
                    $modal_wake_on_lan_host.modal('hide');
                    toastr.success('Wake on Lan Host Save successfully');
                },
                error: function (jqXHR, exception) {
                    const responseJson = jQuery.parseJSON(jqXHR.responseText);
                    toastr.error(responseJson['message']);

                    if (typeof (console) != 'undefined')
                        console.log(exception);
                }
            });

            return false;
        },
        rules: {
            name: {
                required: true,
            },
            mac_address: {
                required: true,
                mac: true,
            }
        },
        messages: {
            name: {
                required: "Please enter a name"
            },
            mac_address: {
                required: "Please enter a Mac Address"
            }
        },
        errorElement: 'span',
        errorPlacement: function (error, element) {
            error.addClass('invalid-feedback');
            element.closest('.form-group').append(error);
        },
        highlight: function (element) {
            $(element).addClass('is-invalid');
        },
        unhighlight: function (element) {
            $(element).removeClass('is-invalid');
        }
    });

    $modal_wake_on_lan_host.on('show.bs.modal', function (e) {
        const $btn = $(e.relatedTarget);
        validator.resetForm();
        $macAddress.removeClass('is-invalid');

        $name.val($btn.data('name'));
        $macAddress.val($btn.data('mac-address'));
        $oldMacAddress.val($btn.data('mac-address'));
    });
});
