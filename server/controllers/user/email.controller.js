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
        email: Joi.string().email().required()
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
    const { uid, email } = value;

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

    const de = await Email.findOne({
        uid,
        value: email
    }).sort({ updatedAt: -1 }).exec();

    if (de) {
        await ems({
            to: email,
            subject: `Mobile Alert`,
            html: `Someone wants to add another email address to your account.
                        If you want to log in to your account, use the login page.`
        });
        return res.status(409).json({
            "status": "error",
            "data": null,
            "detail": `Email '${email}' is already taken`,
            ...ErrorTypes[409]
        });
    }

    if (!dur.canCreate) {
        if (req.user.id !== uid) {
            const dau = await Access.findOne({
                refid: uid,
                refu: req.user.id
            }).exec();

            if (!dau) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `The reference does not belong to you`,
                    ...ErrorTypes[403]
                });
            }

            if (!dau.canCreateEmail) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `You are not allowed to create the email`,
                    ...ErrorTypes[403]
                });
            }
        }
    }

    const token = Math.floor(1000 + Math.random() * 9000);

    const der = await Email.create(new Email({
        value: email,
        uid,
        actor: req.user.id,
        verifyToken: {
            token,
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        },
        privacy: []
    }));

    if (!der) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Creating email has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    await ems({
        to: email,
        subject: `Verification Alert`,
        html: `Confirm Code: ${token}`
    });

    return res.json({
        "status": "success",
        "data": der.toJSON(),
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
            "detail": 'User not found',
            ...ErrorTypes[401]
        });
    }

    const de = await Email.update({
        'verifyToken.token': token,
        'verifyToken.expires': { $gt: new Date(Date.now()) }
    });

    if (!de) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Email not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canVerify) {
        if (req.user.id !== de.uid) {
            const dau = await Access.findOne({
                refid: de.uid,
                refu: req.user.id
            }).exec();

            if (!dau) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `The reference does not belong to you`,
                    ...ErrorTypes[403]
                });
            }

            if (!dau.canVerifyEmail) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `You are not allowed to verify the email`,
                    ...ErrorTypes[403]
                });
            }
        }
    }

    de.verifiedDate = new Date(Date.now());
    const der = await de.save();

    return res.json({
        "status": "success",
        "data": der.toJSON(),
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
            "detail": 'User not found',
            ...ErrorTypes[401]
        });
    }

    const de = await Email.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!de) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Email not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canRemove) {
        if (req.user.id !== de.uid) {
            const dau = await Access.findOne({
                refid: de.uid,
                refu: req.user.id
            }).exec();

            if (!dau) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `The reference does not belong to you`,
                    ...ErrorTypes[403]
                });
            }

            if (!dau.canRemoveEmail) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `You are not allowed to remove the email`,
                    ...ErrorTypes[403]
                });
            }
        }
    }

    const der = await Email.findOneAndRemove({
        _id: id
    });

    if (!der) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Removing has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    return res.json({
        "status": "success",
        "data": der.toJSON(),
        "detail": `Email removed successfully`,
        ...ErrorTypes[200]
    });
}

const edit = async(req, res, next) => {
    const schema = Joi.object({
        id: Joi.string().required(),
        email: Joi.string().email().required()
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

    const { id, email } = value;
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

    const de = await Email.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!de) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Email not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canEdit) {
        if (req.user.id !== de.uid) {
            if (de.isPrivate) {
                const dau = await Access.findOne({
                    refid: de.uid,
                    refu: req.user.id
                }).exec();

                if (!dau) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `The reference does not belong to you`,
                        ...ErrorTypes[403]
                    });
                }

                if (!dau.canEditEmail) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `You are not allowed to edit the email`,
                        ...ErrorTypes[403]
                    });
                }
            }
        }
    }

    const der = await Email.findOneAndUpdate({
        _id: id
    }, {
        value: email
    });

    if (!der) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Updating has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    return res.json({
        "status": "success",
        "data": der.toJSON(),
        "detail": `Email edited successfully`,
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
            "detail": 'User not found',
            ...ErrorTypes[401]
        });
    }

    const de = await Email.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!de) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Email not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canGet) {
        if (req.user.id !== de.uid) {
            if (de.isPrivate) {
                const dau = await Access.findOne({
                    refid: de.uid,
                    refu: req.user.id
                }).exec();

                if (!dau) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `The reference does not belong to you`,
                        ...ErrorTypes[403]
                    });
                }

                if (!dau.canGetEmail) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `You are not allowed to get the email`,
                        ...ErrorTypes[403]
                    });
                }
            }
        }
    }

    return res.json({
        "status": "success",
        "data": de.toJSON(),
        "detail": `Email excuted successfully`,
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
            "detail": 'User not found',
            ...ErrorTypes[401]
        });
    }

    const docsEmail = await Email.find({
        uid
    }).sort({ updatedAt: -1 }).exec();

    if (!docsEmail) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Email not found',
            ...ErrorTypes[404]
        });
    }

    const der = docsEmail.reduce(async(result, email) => {
        if (!dur.canGet) {
            if (req.user.id !== email.uid) {
                if (email.isPrivate) {
                    const dau = await Access.findOne({
                        refid: email.uid,
                        refu: req.user.id
                    }).exec();

                    if (!dau) {
                        return result;
                    }

                    if (!dau.canGetEmail) {
                        return result;
                    }
                }
            }
        }
        result.push(email);
        return result;
    }, []);

    return res.json({
        "status": "success",
        "data": JSON.stringify(await der),
        "detail": `Emails excuted successfully`,
        ...ErrorTypes[200]
    });
}

const check = async(req, res, next) => {
    const schema = Joi.object({
        email: Joi.string().required()
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

    const { email } = value;

    const de = await Email.findOne({
        value: email
    }).sort({ updatedAt: -1 }).exec();

    if (!de) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Email not found',
            ...ErrorTypes[404]
        });
    }

    return res.json({
        "status": "success",
        "data": de.toJSON(),
        "detail": `${email} already taken`,
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
            "detail": 'User not found',
            ...ErrorTypes[401]
        });
    }

    const de = await Email.findOne({
        _id: id
    }).exec();

    if (!de) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'Email not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canPermote) {
        if (req.user.id !== de.uid) {
            const dau = await Access.findOne({
                refid: de.uid,
                refu: req.user.id
            }).exec();

            if (dur.isPrivate) {
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
                        "detail": `You are not allowed to permote the email`,
                        ...ErrorTypes[403]
                    });
                }
            }
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

    if (de.privacy.some(x => x === term)) {
        const rp = await Email.update({
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
        const rp = await Email.update({
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

router.post(`/create`, verifyJWT(), create);
router.post(`/verify`, verifyJWT(), verify);
router.post(`/remove`, verifyJWT(), remove);
router.post(`/edit`, verifyJWT(), edit);
router.post(`/get`, verifyJWT(), get);
router.post(`/check`, check);
router.post(`/gets`, verifyJWT(), gets);
router.post(`/permote`, verifyJWT(), permote);

module.exports = router;