$.cookie.json = true;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

var app = {
    accept: ["active"],
    alias: null,
    password: null
};

// Manifest
var manifest = {
    data: {
        accept: ["active"],
        alias: null,
        password: null
    },

    ui: {
        "#input-password": {
            init: function($node, runtime) {
                $node.attr("data-content", $("#popover-password").html());
            },
            bind: function(data, value, $control) {
                if (value !== null) {
                    data.password = value;
                }
                return data.password;
            },
            check: function(data, value, $control) {
                if (value !== null) {
                    if (!/^(.*[a-z].*)$/i.test(value)) {
                        $('#letter').removeClass('has-success').addClass('has-danger');
                        $('#letter i').html('clear');
                    } else {
                        $('#letter').removeClass('has-danger').addClass('has-success');
                        $('#letter i').html('done');
                    }
                    if (!/^(.*[A-Z].*)$/i.test(value)) {
                        $('#capital').removeClass('has-success').addClass('has-danger');
                        $('#capital i').html('clear');
                    } else {
                        $('#capital').removeClass('has-danger').addClass('has-success');
                        $('#capital i').html('done');
                    }
                    if (!/^(.*[0-9].*)$/i.test(value)) {
                        $('#number').removeClass('has-success').addClass('has-danger');
                        $('#number i').html('clear');
                    } else {
                        $('#number').removeClass('has-danger').addClass('has-success');
                        $('#number i').html('done');
                    }
                    if (!/^(.*[#?!@$%^&*-].*)$/i.test(value)) {
                        $('#special').removeClass('has-success').addClass('has-danger');
                        $('#special i').html('clear');
                    } else {
                        $('#special').removeClass('has-danger').addClass('has-success');
                        $('#special i').html('done');
                    }
                    if (!/^(.{8,})$/i.test(value)) {
                        $('#length').removeClass('has-success').addClass('has-danger');
                        $('#length i').html('clear');
                    } else {
                        $('#length').removeClass('has-danger').addClass('has-success');
                        $('#length i').html('done');
                    }
                }
            }
        },
        "#accept": {
            bind: function(data, value, $control) {
                if (value !== null) {
                    data.accept = value;
                }
                return data.accept;
            },
            check: function(data, value, $control) {
                if (value === null) {
                    return "Please accept our policy";
                }
            }
        },
        "#input-alias": {
            bind: function(data, value, $control) {
                if (value !== null) {
                    data.alias = value;
                }
                return data.alias;
            },
            delay: 150,
            check: function(data, value, $control) {
                $("#group-alias").removeClass('has-success').removeClass('has-danger');
                $("#input-alias-feedback").html("");
                if (value !== null && value.length > 3) {
                    const xhr = $.ajax({
                        url: 'api/aliases/check',
                        type: "post",
                        contentType: 'application/json',
                        data: JSON.stringify({
                            alias: value
                        }),
                        async: false,
                        dataType: 'json'
                    });
                    if (xhr.status === 200) {
                        $("#group-alias").removeClass('has-danger').addClass('has-success');
                        $("#input-alias-feedback").html("done");
                    } else {
                        $("#group-alias").removeClass('has-success').addClass('has-danger');
                        $("#input-alias-feedback").html("clear");
                    }
                }
            }
        }
    }
}

jQuery(document).ready(function() {
    const account = $.cookie('cookie-app-account');
    if (account !== undefined) {
        //$(location).prop('href', '/app');
    }
    //$("btn-sign-in")
    var form = $("#wizard");
    form.my(manifest, app);
});