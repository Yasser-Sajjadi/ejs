const verifyJWT = require("../../middleware/authenticateJWT");
const User = require("../../models/user/user.model");
const ErrorTypes = require("../../middleware/error");
const Access = require("../../models/post/access.model");
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { express, Router } = require("express");
const { mongoose, Schema, Types } = require("mongoose");
const config = require("../../config.json");
const RefreshToken = require("../../models/user/refresh-token.model");
const Mobile = require("../../models/user/mobile.model");
const Alias = require("../../models/user/alias.model");
const Email = require("../../models/user/email.model");
const Password = require("../../models/user/password.model");
const sms = require("../../middleware/send-sms");

const create = async(req, res) => {
    const schema = Joi.object({
        alias: Joi.string().required().pattern(new RegExp('^(([A-Za-z0-9]+)(?:[. @_-][A-Za-z0-9]+)*){3,}$')),
        accept: Joi.boolean().valid(true).required(),
        password: Joi.string().required().pattern(new RegExp('^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$'))
    });

    const { error, value } = schema.validate({...req.body, ...req.params });

    if (error) {
        return res.status(400).json({
            "status": "error",
            "data": error,
            "detail": 'Invalid requested data',
            ...ErrorTypes[400]
        });
    }

    const { alias, password } = value;

    const token = Math.floor(1000 + Math.random() * 9000);

    const du = await User.create(new User({
        verifyToken: {
            token,
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        },
        privacy: [],
        acceptTerms: [
            'create', 'edit', 'get', 'verify', 'remove', 'permote', 'get-token',
            'create-password', 'edit-password', 'get-password', 'verify-password', 'remove-password', 'permote-password',
            'create-mobile', 'edit-mobile', 'get-mobile', 'verify-mobile', 'remove-mobile', 'permote-mobile',
            'create-email', 'edit-email', 'get-email', 'verify-email', 'remove-email', 'permote-email',
            'create-post', 'edit-post', 'get-post', 'verify-post', 'remove-post', 'permote-post',
            'create-sketch', 'edit-sketch', 'get-sketch', 'verify-sketch', 'remove-sketch', 'permote-sketch',
            'private', 'confirm', 'active', 'pin'
        ]
    }));

    if (!du) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `The operation has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    const daf = await Alias.findOne({
        value: alias
    }).sort({ updatedAt: -1 }).exec();

    if (daf) {
        return res.status(409).json({
            "status": "error",
            "data": null,
            "detail": `Alias '${alias}' has token before`,
            ...ErrorTypes[409]
        });
    }

    const da = await Alias.create(new Alias({
        value: alias,
        uid: du._id,
        actor: du._id,
        verifyToken: {
            token,
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        }
    }));

    if (!da) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Append new alias has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    const dp = await Password.create(new Password({
        value: bcrypt.hashSync(password, 10),
        uid: du._id,
        actor: du._id,
        verifyToken: {
            token,
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        }
    }));

    if (!dp) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Append new password has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    const dau = await Access.create(new Access({
        relations: [du._id],
        actor: du._id,
        privacy: [
            'create', 'edit', 'get', 'verify', 'remove', 'permote', 'get-token',
            'create-password', 'edit-password', 'get-password', 'verify-password', 'remove-password', 'permote-password',
            'create-mobile', 'edit-mobile', 'get-mobile', 'verify-mobile', 'remove-mobile', 'permote-mobile',
            'create-email', 'edit-email', 'get-email', 'verify-email', 'remove-email', 'permote-email',
            'create-post', 'edit-post', 'get-post', 'verify-post', 'remove-post', 'permote-post',
            'create-sketch', 'edit-sketch', 'get-sketch', 'verify-sketch', 'remove-sketch', 'permote-sketch',
            'private', 'confirm', 'active', 'pin'
        ]
    }));

    if (!dau) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Wrong create access`,
            ...ErrorTypes[500]
        });
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = jwt.sign({ sub: du._id, id: du._id }, config.secret, { expiresIn: '15m' });

    const refreshToken = await RefreshToken.create(generateRefreshToken({
        uid: du._id,
        ip: req.ip
    }));

    setTokenCookie(res, refreshToken.token);

    return res.json({
        "status": "success",
        "data": {
            ...du.toJSON(),
            alias: da,
            jwt: {
                token: jwtToken,
                createdAt: Date.now(),
                expires: new Date(Date.now() + 15 * 60 * 60 * 1000),
                span: 15 * 60 * 60 * 1000
            },
            refreshToken: refreshToken.toJSON()
        },
        "detail": `authenticated`,
        ...ErrorTypes[200]
    });
};

const verify = async(req, res, next) => {
    const schema = Joi.object({
        token: Joi.string().required()
    });

    const { error, value } = schema.validate({...req.body, ...req.params });
    if (error) {
        return res.status(400).json({
            "status": "error",
            "data": error,
            "detail": 'Invalid requested data',
            ...ErrorTypes[400]
        });
    }

    const { token } = value;
    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `User not found`,
            ...ErrorTypes[401]
        });
    }

    const du = await User.findOne({
        "verifyToken.token": token,
        "verifyToken.expires": new Date(Date.now())
    }).exec();

    if (!du) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `Token not found`,
            ...ErrorTypes[404]
        });
    }

    if (!dur.canVerify) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: du._id } },
                { relations: { $elemMatch: req.user.id } }
            ]
        }).exec();

        if (!dau) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `The reference does not belong to you`,
                ...ErrorTypes[403]
            });
        }

        if (!dau.canVerify) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to verify the mobile`,
                ...ErrorTypes[403]
            });
        }
    }

    du.verifiedDate = new Date(Date.now());
    await du.save();

    const dp = await Password.update({
        'verifyToken.token': token,
        'verifyToken.expires': { $gt: new Date(Date.now()) }
    });

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Password not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canVerify) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: dp.uid } },
                { relations: { $elemMatch: req.user.id } }
            ]
        }).exec();

        if (!dau) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `The reference does not belong to you`,
                ...ErrorTypes[403]
            });
        }

        if (!dau.canVerifyPassword) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to verify the password`,
                ...ErrorTypes[403]
            });
        }
    }

    dp.verifiedDate = new Date(Date.now());
    const dpr = await dp.save();

    return res.json({
        "status": "success",
        "data": du.toJSON(),
        "detail": `Verification code sent`,
        ...ErrorTypes[200]
    });
};

const get = async(req, res) => {
    const schema = Joi.object({
        id: Joi.string().required()
    });

    const { error, value } = schema.validate({...req.body, ...req.params });
    if (error) {
        return res.status(400).json({
            "status": "error",
            "data": error,
            "detail": 'Invalid requested data',
            ...ErrorTypes[400]
        });
    }

    const { id } = value;

    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `User not found`,
            ...ErrorTypes[401]
        });
    }

    if (!dur.canGet) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: id } },
                { relations: { $elemMatch: req.user.id } }
            ]
        }).exec();

        if (!dau) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `The reference does not belong to you`,
                ...ErrorTypes[403]
            });
        }

        if (!dau.canGetMobile) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to get the user`,
                ...ErrorTypes[403]
            });
        }
    }

    const du = await User.findOne({ _id: id })
        .populate('email')
        .populate('mobile')
        .populate('password')
        .populate('emails')
        .populate('mobiles')
        .populate('tokens')
        .lean()
        .exec();

    if (!du) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `User not found`,
            ...ErrorTypes[401]
        });
    }

    return res.json({
        "status": "success",
        "data": du.toJSON(),
        "detail": `Successfully get data`,
        ...ErrorTypes[200]
    });
};

const gets = async(req, res) => {
    const schema = Joi.object({
        id: Joi.string().required()
    });

    const { error, value } = schema.validate({...req.body, ...req.params });
    if (error) {
        return res.status(400).json({
            "status": "error",
            "data": error,
            "detail": 'Invalid requested data',
            ...ErrorTypes[400]
        });
    }

    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `User not found`,
            ...ErrorTypes[401]
        });
    }

    const dsu = await User.find({

    }).exec();

    if (!dsu) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Mobile not found',
            ...ErrorTypes[404]
        });
    }

    const dsur = dsu.reduce((result, u) => {
        result.push(u);
        return result;
    }, []);

    return res.json({
        "status": "success",
        "data": JSON.stringify(dsur),
        "detail": `Successfully get data`,
        ...ErrorTypes[200]
    });
};

const permote = async(req, res) => {
    const schema = Joi.object({
        id: Joi.string().required(),
        term: Joi.string().required()
    });

    const { error, value } = schema.validate({...req.body, ...req.params });
    if (error) {
        return res.status(400).json({
            "status": "error",
            "data": error,
            "detail": 'Invalid requested data',
            ...ErrorTypes[400]
        });
    }

    const { id, term } = value;

    const dur = await User.findOne({
        _id: req.user.id
    }).populate("acceptedTerms").exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `User not found`,
            ...ErrorTypes[401]
        });
    }

    if (!dur.canPermote) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: id } },
                { relations: { $elemMatch: req.user.id } }
            ]
        }).exec();

        if (!dau) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `The reference does not belong to you`,
                ...ErrorTypes[403]
            });
        }

        if (!dau.canPermote) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to permote the user`,
                ...ErrorTypes[403]
            });
        }
    }

    if (!dur.acceptTerms.some(x => x === term)) {
        return res.status(406).json({
            "status": "error",
            "data": null,
            "detail": `privacy '${term}' not defined`,
            ...ErrorTypes[406]
        });
    }

    if (dur.privacy.some(x => x === term)) {
        const dur = await User.update({
            _id: id,
        }, {
            $pull: {
                privacy: term
            }
        }, {
            multi: false
        });
        return res.json({
            "status": "success",
            "data": dur.toJSON(),
            "detail": `Successfully permote term ${term}`,
            ...ErrorTypes[200]
        });
    } else {
        const dur = await User.update({
            _id: id
        }, {
            $push: {
                privacy: term
            }
        }, {
            multi: false
        });
        return res.json({
            "status": "success",
            "data": dur.toJSON(),
            "detail": `Successfully permote term ${term}`,
            ...ErrorTypes[200]
        });
    }
};

const authenticate = async(req, res, next) => {
    const schema = Joi.object({
        uid: Joi.string().required(),
        password: Joi.string().required()
    });
    const { error, value } = schema.validate({...req.body, ...req.params });
    if (error) {
        return res.status(400).json({
            "status": "error",
            "data": error,
            "detail": 'Invalid requested data',
            ...ErrorTypes[400]
        });
    }
    const { uid, password } = value;

    const ip = req.ip;

    const du = await User.findOne({
        _id: uid
    }).exec();

    if (!du) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `User not found`,
            ...ErrorTypes[401]
        });
    }

    const dps = await Password.find({
        uid
    }).sort({ updatedAt: -1 }).exec();

    const dpsr = dps.reduce((result, p) => {
        if (p && bcrypt.compareSync(password, p.value)) {
            result.push(p);
        }
        return result;
    }, []);

    if (!dpsr || !(dpsr.length > 0)) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `Wrong password`,
            ...ErrorTypes[401]
        });
    }

    const da = await Alias.findOne({
        uid
    }).exec();

    if (!du) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Confelict in load alias`,
            ...ErrorTypes[500]
        });
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = jwt.sign({ sub: uid, id: uid }, config.secret, { expiresIn: '15m' });

    const refreshToken = await RefreshToken.create(generateRefreshToken({
        uid,
        ip
    }));

    if (!refreshToken) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `Refresh token not created`,
            ...ErrorTypes[404]
        });
    }

    setTokenCookie(res, refreshToken.token);

    return res.json({
        "status": "success",
        "data": {
            ...du.toJSON(),
            alias: da,
            jwt: {
                token: jwtToken,
                createdAt: Date.now(),
                expires: new Date(Date.now() + 15 * 60 * 60 * 1000),
                span: 15 * 60 * 60 * 1000
            },
            refreshToken: refreshToken.toJSON()
        },
        "detail": `authenticated`,
        ...ErrorTypes[200]
    });
}

const refreshToken = async(req, res, next) => {
    const token = req.cookies.refreshToken;
    const ip = req.ip;

    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `Unauthorized`,
            ...ErrorTypes[401]
        });
    }

    const revokedToken = await RefreshToken.findOne({
        token
    }).exec();

    if (!revokedToken) {
        return res.status(409).json({
            "status": "error",
            "data": null,
            "detail": `Token is expired`,
            ...ErrorTypes[409]
        });
    }

    if (!dur.canGetToken) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: revokedToken.uid } },
                { relations: { $elemMatch: req.user.id } }
            ]
        }).exec();

        if (!dau) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `illegal access`,
                ...ErrorTypes[403]
            });
        }

        if (!dau.canGetToken) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `Your access to the token is restricted`,
                ...ErrorTypes[403]
            });
        }
    }

    // replace old refresh token with a new one and save
    const refreshToken = await RefreshToken.create(generateRefreshToken({
        uid: revokedToken.uid,
        ip
    }));

    if (!refreshToken) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Refresh token not created`,
            ...ErrorTypes[500]
        });
    }

    revokedToken.revoked = new Date(Date.now());
    revokedToken.revokedByIp = ip;
    revokedToken.replacedByToken = refreshToken.token;
    revokedToken.save();

    // generate new jwt
    const jwtToken = jwt.sign({
            sub: revokedToken.uid,
            id: revokedToken.uid
        },
        config.secret, { expiresIn: '15m' }
    );

    setTokenCookie(res, refreshToken.token);

    const du = await User.findOne({
        _id: revokedToken.uid
    }).exec();

    if (!du) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `User not acceptable`,
            ...ErrorTypes[500]
        });
    }

    return res.json({
        "status": "success",
        "data": {
            ...du.toJSON(),
            jwt: {
                token: jwtToken,
                createdAt: Date.now(),
                expires: new Date(Date.now() + 15 * 60 * 60 * 1000),
                span: 15 * 60 * 60 * 1000
            },
            refreshToken: refreshToken.toJSON()
        },
        "detail": `Token is refreshed`,
        ...ErrorTypes[200]
    });
}

const revokeToken = async(req, res, next) => {
    const schema = Joi.object({
        token: Joi.string().empty('')
    });
    const { error, value } = schema.validate({...req.body, ...req.params });
    if (error) {
        return res.status(400).json({
            "status": "error",
            "data": error,
            "detail": 'Invalid requested data',
            ...ErrorTypes[400]
        });
    }
    // accept token from request body or cookie
    const token = value.token || req.cookies.refreshToken;
    const ip = req.ip;

    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `User not found`,
            ...ErrorTypes[401]
        });
    }

    const refreshToken = await RefreshToken.findOne({
        token
    }).exec();

    if (!refreshToken) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `refresh token not found`,
            ...ErrorTypes[404]
        });
    }


    if (!dur.canGetToken) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: refreshToken.uid } },
                { relations: { $elemMatch: req.user.id } }
            ]
        }).exec();

        if (!dau) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `The reference does not belong to you`,
                ...ErrorTypes[403]
            });
        }

        if (!dau.canGetToken) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `Token not acceptable`,
                ...ErrorTypes[403]
            });
        }
    }

    const du = await User.findOne({
        _id: refreshToken.uid
    }).exec();

    if (!du) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `User not acceptable`,
            ...ErrorTypes[404]
        });
    }

    // revoke token and save
    refreshToken.revoked = new Date(Date.now());
    refreshToken.revokedByIp = ip;
    refreshToken.save();

    setTokenCookie(res, refreshToken.token);

    return res.json({
        "status": "success",
        "data": {
            ...du.toJSON(),
            refreshToken: refreshToken.toJSON()
        },
        "detail": `Token revoked`,
        ...ErrorTypes[200]
    });
}

const refreshTokens = async(req, res, next) => {
    // users can get their own refresh tokens and admins can get any user's refresh tokens
    const { uid } = req.body;

    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `User not found`,
            ...ErrorTypes[401]
        });
    }

    if (!dur.canGetToken) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: uid } },
                { relations: { $elemMatch: req.user.id } }
            ]
        }).exec();
        if (!dau) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `The reference does not belong to you`,
                ...ErrorTypes[403]
            });
        }

        if (!dau.canGetToken) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `Token not acceptable`,
                ...ErrorTypes[403]
            });
        }
    }

    const refreshTokens = await RefreshToken.find({
        uid
    }).sort({ updatedAt: -1 }).lean().exec();

    if (!refreshTokens) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `Refresh token not found`,
            ...ErrorTypes[404]
        });
    }

    return res.json({
        "status": "success",
        "data": JSON.stringify(refreshTokens),
        "detail": `Successfully get refresh tokens`,
        ...ErrorTypes[200]
    });
}

const generateRefreshToken = (uid, ip) => {
    const hash = crypto.createHash('sha256')
        // updating data
        .update(ip)
        // Encoding to be used
        .digest('hex');
    // create a refresh token that expires in 7 days
    return new RefreshToken({
        uid,
        token: hash,
        expiresDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        createdByIp: ip
    });
}

const setTokenCookie = (res, token) => {
    // create http only cookie with refresh token that expires in 7 days
    const cookieOptions = {
        httpOnly: true,
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    };
    res.cookie('refreshToken', token, cookieOptions);
}

const router = Router();

router.post(`/create`, create);
router.post(`/verify`, verifyJWT(), verify);
router.post(`/get`, verifyJWT(), get);
router.post(`/gets`, verifyJWT(), gets);
router.post(`/permote`, verifyJWT(), permote);
router.post(`/authenticate`, authenticate);
router.post(`/refresh-token`, verifyJWT(), refreshToken);
router.post(`/revoke-token`, verifyJWT(), revokeToken);
router.post(`/refresh-tokens`, verifyJWT(), refreshTokens);

module.exports = router;