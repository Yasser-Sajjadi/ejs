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
const { generateRefreshToken, setTokenCookie } = require("./user.controller");

const create = async(req, res, next) => {
    const schema = Joi.object({
        uid: Joi.string().required(),
        password: Joi.string().pattern(new RegExp('^(?:(?!(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}).)*$')),
        confirm: Joi.ref('password')
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
    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": 'User not found',
            ...ErrorTypes[401]
        });
    }

    if (!dur.canCreate) {
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

        if (!dau.canCreatePassword) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to create the mobile`,
                ...ErrorTypes[403]
            });
        }
    }

    const token = Math.floor(1000 + Math.random() * 9000);

    const dp = await Password.create(new Password({
        value: bcrypt.hashSync(password, 10),
        actor: req.user.id,
        verifyToken: {
            token,
            expires: new Date(Date.now() + 24 * 60 * 60 * 1000)
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

    return res.json({
        "status": "success",
        "data": dp.toJSON(),
        "detail": `Token created successfully`,
        ...ErrorTypes[200]
    });
}

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
        "data": dpr.toJSON(),
        "detail": `Password verified successfully`,
        ...ErrorTypes[200]
    });
}

const remove = async(req, res, next) => {
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

    const dp = await Password.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Password not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canRemove) {
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

        if (!dau.canRemovePassword) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to create the mobile`,
                ...ErrorTypes[403]
            });
        }
    }

    const dpr = await Password.findOneAndRemove({
        _id: id
    });

    if (!dpr) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Password removing has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    return res.json({
        "status": "success",
        "data": dpr.toJSON(),
        "detail": `Password removed successfully`,
        ...ErrorTypes[200]
    });
}

const get = async(req, res, next) => {
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

    const dp = await Password.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Password not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canGet) {
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

        if (!dau.canGetMobile) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to create the mobile`,
                ...ErrorTypes[403]
            });
        }
    }

    return res.json({
        "status": "success",
        "data": dp.toJSON(),
        "detail": `Password geted successfully`,
        ...ErrorTypes[200]
    });
}

const gets = async(req, res, next) => {
    const schema = Joi.object({
        uid: Joi.string().required()
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
    const { uid } = value;

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

    const dsp = await Password.find({
        refid: uid
    }).sort({ updatedAt: -1 }).exec();

    if (!dsp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Password not found',
            ...ErrorTypes[404]
        });
    }

    const dspr = dsp.reduce(async(result, doc) => {
        if (!dur.canGet) {
            const dau = await Access.findOne({
                $and: [
                    { relations: { $elemMatch: doc.uid } },
                    { relations: { $elemMatch: req.user.id } }
                ]
            }).exec();

            if (!dau) {
                return result;
            }

            if (!dau.canGetPassword) {
                return result;
            }
        }
        result.push(doc);
        return result;
    }, []);

    return res.json({
        "status": "success",
        "data": JSON.stringify(await dspr),
        "detail": `Password goted successfully`,
        ...ErrorTypes[200]
    });
}

const permote = async(req, res, next) => {
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
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": `User not found`,
            ...ErrorTypes[401]
        });
    }

    const dp = await Password.findOne({
        _id: id
    }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Password not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canPermote) {
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

        if (!dau.canPermotePassword) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to create the mobile`,
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

    if (dp.privacy.some(x => x === term)) {
        const rp = await Password.update({
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
            "data": rp.toJSON(),
            "detail": `Password permoted successfully`,
            ...ErrorTypes[200]
        });
    } else {
        const rp = await Password.update({
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
            "data": rp.toJSON(),
            "detail": `Password permoted successfully`,
            ...ErrorTypes[200]
        });
    }
}


const router = Router();

router.post(`/create`, create);
router.post(`/verify`, verifyJWT(), verify);
router.post(`/remove`, verifyJWT(), remove);
router.post(`/get`, verifyJWT(), get);
router.post(`/gets`, verifyJWT(), gets);
router.post(`/permote`, verifyJWT(), permote);


module.exports = router;