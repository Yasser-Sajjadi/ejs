$.cookie.json = true;

function validateMobile(phone) {
    const re = /^\s*(?:\+?(\d{1,3}))?([-. (]*(\d{3})[-. )]*)?((\d{3})[-. ]*(\d{2,4})(?:[-.x ]*(\d+))?)\s*$/;
    return re.test(String(phone).toLowerCase());
}

function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}

function validateAlias(alias) {
    const re = /^(([A-Za-z0-9]+)(?:[. @_-][A-Za-z0-9]+)*){3,18}$/;
    return re.test(String(alias).toLowerCase());
}

function navigateTo(page, title, url) {
    if ("undefined" !== typeof history.pushState) {
        history.pushState({ page: page }, title, url);
    } else {
        window.location.assign(url);
    }
}

const signByUid = (uid, password) => {
    $.ajax({
        url: 'api/users/authenticate',
        type: "post",
        contentType: 'application/json',
        data: JSON.stringify({
            uid: uid,
            password: password
        }),
        dataType: 'json',
        success: function(res) {
            $.cookie('cookie-app-account', {
                id: res.data._id,
                alias: res.data.alias.value,
                jwt: res.data.jwt.token,
                token: res.data.refreshToken.token,
                password: password
            }, {
                expires: 7
            });
            console.log({
                id: res.data._id,
                alias: res.data.alias.value,
                jwt: res.data.jwt.token,
                token: res.data.refreshToken.token
            })
            $("#app-body").html("/app");
        },
        error: function(xhr, ajaxOptions, thrownError) {
            console.info(xhr.responseJSON);
        }
    });
}

jQuery(document).ready(() => {
    var binds = Bind({
        "bind-id": null,
        "bind-password": null,
        "bind-errors": [],
        "bind-type": "alias"
    }, {
        "bind-id": '#input-id',
        "bind-password": '#input-password',
        "bind-errors": {
            dom: '#div-errors',
            transform: function(value) {
                return '<p class="mb-0 alert-footing">' + value["bind-message"] + '</p>';
            },
        }
    });

    //$(".alert").alert("close");


    $(document).on('click', '#btn-get-start', (event) => {
        event.preventDefault();
        $(".alert").removeClass("collapse").addClass("collapse");
        binds["bind-errors"] = [];
        if ((binds["bind-id"] === null) || (binds["bind-id"].length <= 0)) {
            binds["bind-errors"].push({
                code: 6001,
                "bind-message": `Identifier is not entered or is incorrect.`
            });
            $("#input-id").focus();
        }

        if ((binds["bind-password"] === null) || (binds["bind-password"].length <= 0)) {
            binds["bind-errors"].push({
                code: 6002,
                "bind-message": `Password not entered.`
            });
            if (!/^(.*[a-z].*)$/i.test(binds["bind-password"])) {
                binds["bind-errors"].push({
                    code: 6003,
                    "bind-message": `<em>The password must at least <strong>one letter</strong></em>`
                });
            }
            if (!/^(.*[A-Z].*)$/i.test(binds["bind-password"])) {
                binds["bind-errors"].push({
                    code: 6004,
                    "bind-message": `<em>The password must at least <strong>one capital letter</strong></em>`
                });
            }
            if (!/^(.*[0-9].*)$/i.test(binds["bind-password"])) {
                binds["bind-errors"].push({
                    code: 6005,
                    "bind-message": `<em>The password must at least <strong>one number</strong></em>`
                });
            }
            if (!/^(.*[#?!@$%^&*-].*)$/i.test(binds["bind-password"])) {
                binds["bind-errors"].push({
                    code: 6006,
                    "bind-message": `<em>The password must at least <strong>one special letter</strong></em>`
                });
            }
            if (!/^(.{8,})$/i.test(binds["bind-password"])) {
                binds["bind-errors"].push({
                    code: 6007,
                    "bind-message": `<em>The password must be at least <strong>8 characters</strong></em>`
                });
            }
        }

        if (binds["bind-errors"].length > 0) {
            console.info(binds);
            return $(".alert").removeClass("collapse");
        }

        if (binds["bind-type"] === "mobile") {
            $.ajax({
                url: 'api/mobiles/check',
                type: "post",
                contentType: 'application/json',
                data: JSON.stringify({
                    mobile: binds["bind-id"]
                }),
                dataType: 'json',
                success: function(res) {
                    signByUid(res.data.uid, binds["bind-password"])
                },
                error: function(xhr, ajaxOptions, thrownError) {
                    console.info(xhr.responseJSON);
                }
            });
        } else if (binds["bind-type"] === "email") {
            $.ajax({
                url: 'api/emails/check',
                type: "post",
                contentType: 'application/json',
                data: JSON.stringify({
                    email: binds["bind-id"]
                }),
                dataType: 'json',
                success: function(res) {
                    signByUid(res.data.uid, binds["bind-password"])
                },
                error: function(xhr, ajaxOptions, thrownError) {
                    console.info(xhr.responseJSON);
                }
            });
        } else if (binds["bind-type"] === "alias") {
            $.ajax({
                url: 'api/aliases/check',
                type: "post",
                contentType: 'application/json',
                data: JSON.stringify({
                    alias: binds["bind-id"]
                }),
                dataType: 'json',
                success: function(res) {
                    signByUid(res.data.uid, binds["bind-password"])
                },
                error: function(xhr, ajaxOptions, thrownError) {
                    console.info(xhr.responseJSON);
                }
            });
        } else {
            signByUid(binds["bind-id"], binds["bind-password"])
        }
    });

    //$.removeCookie('cookie-app-account');
    const account = $.cookie('cookie-app-account');
    if (account !== undefined) {
        binds["bind-id"] = account.alias;
        $.ajax({
            url: 'api/users/refresh-token',
            type: "POST",
            contentType: 'application/json',
            headers: {
                Authorization: `Bearer ${account.jwt}`
            },
            dataType: 'json',
            success: function(res) {
                $.cookie('cookie-app-account', {
                    id: account.id,
                    alias: res.data.alias.value,
                    jwt: res.data.jwt.token,
                    token: res.data.refreshToken.token,
                    password: account.password
                }, {
                    expires: 7
                });
                console.log({
                    id: res.data._id,
                    alias: res.data.alias.value,
                    jwt: res.data.jwt.token,
                    token: res.data.refreshToken.token
                })
                navigateTo("HomePage", "Home Page", "/app");
            },
            error: function(xhr, ajaxOptions, thrownError) {
                console.info(xhr.responseJSON);
            }
        });
    }
});