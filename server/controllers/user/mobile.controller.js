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
        mobile: Joi.string().required()
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

    const { uid, mobile } = value;
    console.log({ uid, mobile });

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

    const dm = await Mobile.findOne({
        uid,
        value: mobile
    }).sort({ updatedAt: -1 }).exec();

    if (dm) {
        await sms({
            to: mobile,
            text: `Someone wants to add another mobile address to your account.
                If you want to log in to your account, use the login page.`
        });
        return res.status(409).json({
            "status": "error",
            "data": null,
            "detail": `Mobile '${mobile}' is already taken`,
            ...ErrorTypes[409]
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

        if (!dau.canCreateMobile) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to create the mobile`,
                ...ErrorTypes[403]
            });
        }
    }

    const token = Math.floor(1000 + Math.random() * 9000);

    const dmr = await Mobile.create(new Mobile({
        value: mobile,
        uid,
        actor: req.user.id,
        verifyToken: {
            token,
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        },
        privacy: ['private']
    }));

    if (!dmr) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Registration has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    await sms({
        to: mobile,
        text: `Confirm Code: ${token}`
    });

    return res.json({
        "status": "success",
        "data": dmr.toJSON(),
        "detail": `Verification code sent`,
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

    const dm = await Mobile.findOne({
        "verifyToken.token": token,
        "verifyToken.expires": new Date(Date.now())
    }).exec();

    if (!dm) {
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
                { relations: { $elemMatch: dm.uid } },
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

        if (!dau.canVerifyMobile) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to verify the mobile`,
                ...ErrorTypes[403]
            });
        }
    }

    dm.verifiedDate = new Date(Date.now());
    await dm.save();

    return res.json({
        "status": "success",
        "data": dm.toJSON(),
        "detail": `Verify Seccessfully`,
        ...ErrorTypes[200]
    });
};

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

    const dm = await Mobile.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!dm) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `Mobile not found`,
            ...ErrorTypes[404]
        });
    }

    if (!dur.canRemove) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: dm.uid } },
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

        if (!dau.canRemoveMobile) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to remove the mobile`,
                ...ErrorTypes[403]
            });
        }
    }

    const dmr = await Mobile.findOneAndRemove({
        _id: id
    });

    if (!dmr) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Mobile remove is failed`,
            ...ErrorTypes[500]
        });
    }

    return res.json({
        "status": "error",
        "data": dmr.toJSON(),
        "detail": `Mobile remove`,
        ...ErrorTypes[200]
    });
};

const edit = async(req, res, next) => {
    const schema = Joi.object({
        id: Joi.string().required(),
        mobile: Joi.string().required()
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

    const { id, mobile } = value;
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

    const dm = await Mobile.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!dm) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Mobile not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canEdit) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: dm.uid } },
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

        if (!dau.canEditMobile) {
            return res.status(403).json({
                "status": "error",
                "data": null,
                "detail": `You are not allowed to edit the mobile`,
                ...ErrorTypes[403]
            });
        }
    }

    const dmr = await Mobile.findOneAndUpdate({
        _id: id
    }, {
        value: mobile
    });

    if (!dmr) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Mobile remove is failed`,
            ...ErrorTypes[500]
        });
    }

    return res.json({
        "status": "success",
        "data": dmr.toJSON(),
        "detail": `Successfully mobile updated`,
        ...ErrorTypes[200]
    });
};

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
            "detail": 'User not found',
            ...ErrorTypes[401]
        });
    }

    const dm = await Mobile.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!dm) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Mobile not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canGet) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: dm.uid } },
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
                "detail": `You are not allowed to get the mobile`,
                ...ErrorTypes[403]
            });
        }
    }

    return res.json({
        "status": "success",
        "data": dm.toJSON(),
        "detail": `Successfully get mobile`,
        ...ErrorTypes[200]
    });
};

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
            "detail": 'User not found',
            ...ErrorTypes[401]
        });
    }

    const dsm = await Mobile.find({
        refid: uid
    }).sort({ updatedAt: -1 }).exec();

    if (!dsm) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Mobile not found',
            ...ErrorTypes[404]
        });
    }

    const dsmr = dsm.reduce(async(result, doc) => {
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

            if (!dau.canGetMobile) {
                return result;
            }
        }
        result.push(doc);
        return result;
    }, []);

    res.json({
        "status": "success",
        "data": JSON.stringify(await dsmr),
        "detail": `Successfully gets mobile`,
        ...ErrorTypes[200]
    });
};

const check = async(req, res, next) => {
    const schema = Joi.object({
        mobile: Joi.string().required()
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

    const { mobile } = value;

    const dm = await Mobile.findOne({
        value: mobile
    }).sort({ updatedAt: -1 }).exec();

    if (!dm) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Mobile not found',
            ...ErrorTypes[404]
        });
    }

    return res.json({
        "status": "success",
        "data": dm.toJSON(),
        "detail": `${mobile} already taken`,
        ...ErrorTypes[200]
    });
};

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
            "detail": 'User not found',
            ...ErrorTypes[401]
        });
    }

    const dm = await Mobile.findOne({
        _id: id
    }).exec();

    if (!dm) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Mobile not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canPermote) {
        const dau = await Access.findOne({
            $and: [
                { relations: { $elemMatch: dm.uid } },
                { relations: { $elemMatch: req.user.id } }
            ]
        }).exec();

        if (!dau) {
            return res.status(404).json({
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
                "detail": `You are not allowed to permote the mobile`,
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

    if (dm.privacy.some(x => x === term)) {
        const dmr = await Mobile.update({
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
            "data": dmr.toJSON(),
            "detail": `Successfully permote term ${term}`,
            ...ErrorTypes[200]
        });
    } else {
        const dmr = await Mobile.update({
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
            "data": dmr.toJSON(),
            "detail": `Successfully permote term ${term}`,
            ...ErrorTypes[200]
        });
    }
};

const router = Router();

router.post(`/create`, verifyJWT(), create);
router.post(`/verify`, verifyJWT(), verify);
router.post(`/remove`, verifyJWT(), remove);
router.post(`/edit`, verifyJWT(), edit);
router.post(`/get`, verifyJWT(), get);
router.post(`/gets`, verifyJWT(), gets);
router.post(`/check`, check);
router.post(`/permote`, verifyJWT(), permote);

module.exports = router;