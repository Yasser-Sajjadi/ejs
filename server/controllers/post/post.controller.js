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

const create = async(req, res, next) => {
    const schema = Joi.object({
        uid: Joi.string().required(),
        terms: Joi.array()
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

    const { uid, terms } = value;
    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": 'Unauthorized',
            ...ErrorTypes[401]
        });
    }

    if (!dur.canCreate) {
        if (req.user.id !== uid) {
            if (dur.isPrivate) {
                const dau = await Access.findOne({
                    refid: uid,
                    refu: req.user.id
                }).exec();

                if (!dau) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `This is a private account and you are not allowed to access it`,
                        ...ErrorTypes[403]
                    });
                }

                if (!dau.canCreate) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `You are not allowed to create the post`,
                        ...ErrorTypes[403]
                    });
                }
            }
        }
    }

    const dp = await Post.create(new Post({
        uid,
        actor: req.user.id,
        privacy: terms.reduce((result, term) => {
            if (dur.acceptTerms.some(x => x === term)) {
                result.push(term);
            }
            return result;
        }, [])
    }));

    if (!dp) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `The operation has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    return res.json({
        "status": "success",
        "data": dp.toJSON(),
        "detail": `The operation is successfully`,
        ...ErrorTypes[200]
    });
};

const remove = async(req, res, next) => {
    const schema = Joi.object({
        uid: Joi.string().required(),
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
            "detail": 'Unauthorized',
            ...ErrorTypes[401]
        });
    }

    const dp = await Post.findOne({
        _id: id
    }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `No post with such ID is available`,
            ...ErrorTypes[404]
        });
    }

    if (!dur.canRemove) {
        if (req.user.id !== dp.uid) {
            const dau = await Access.findOne({
                refid: dp.uid,
                refu: req.user.id
            }).exec();

            if (!dau) {
                const dap = await Access.findOne({
                    refid: dp._id,
                    refu: req.user.id
                }).exec();

                if (!dap) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `This is a private account and you are not allowed to access it`,
                        ...ErrorTypes[403]
                    });
                }

                if (!dap.canRemove) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `You are not allowed to remove the post`,
                        ...ErrorTypes[403]
                    });
                }

                if (dap.isBanRemove) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `You are not allowed to remove the post`,
                        ...ErrorTypes[403]
                    });
                }
            }

            if (dau.canRemove) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `You are not allowed to remove the post`,
                    ...ErrorTypes[403]
                });
            }

            if (dau.isBanRemove) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `You are not allowed to remove the post`,
                    ...ErrorTypes[403]
                });
            }
        }
    }

    const dpr = await Post.findOneAndRemove({
        _id: id
    });

    if (!dpr) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `The operation encountered a problem while removing the post ${id}`,
            ...ErrorTypes[500]
        });
    }

    return res.json({
        "status": "success",
        "data": dpr.toJSON(),
        "detail": `The operation is successfully`,
        ...ErrorTypes[200]
    });
};

const gets = async(req, res, next) => {
    const schema = Joi.object({
        uid: Joi.string().required(),
        skip: Joi.number().required(),
        limit: Joi.number().required()
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

    const { uid, skip, limit } = value;
    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": 'Unauthorized',
            ...ErrorTypes[401]
        });
    }

    const duref = await User.findOne({
        _id: uid
    }).exec();

    if (!duref) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'User not found',
            ...ErrorTypes[404]
        });;
    }

    if (!dur.canGet) {
        if (req.user.id !== uid) {
            const dau = await Access.findOne({
                refid: uid,
                refu: req.user.id
            }).exec();

            if (duref.isPrivate) {
                if (!dau) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `This is a private account and you are not allowed to access it`,
                        ...ErrorTypes[403]
                    });
                }

                if (!dau.canGet) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `You are not allowed to get the post`,
                        ...ErrorTypes[403]
                    });
                }
            }

            if (dau.isBanGet) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `This is a private account and you are not allowed to access it`,
                    ...ErrorTypes[403]
                });
            }
        }
    }

    const dps = await Post.find({
            uid
        })
        .sort({ updatedAt: -1 })
        .skip(skip)
        .limit(limit)
        .exec();

    if (!dps) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `The operation encountered a problem while extracting the posts`,
            ...ErrorTypes[500]
        });
    }

    const dpsr = dps.reduce(async(result, post) => {
        if (!dur.canGet) {
            if (post.uid !== req.user.id) {
                const dau = await Access.findOne({
                    refid: uid,
                    refu: req.user.id
                }).exec();

                if (!dau) {
                    return result;
                }

                if (!dau.canGet) {
                    return result;
                }

                if (dau.isBanGet) {
                    return result;
                }

                const dap = await Access.findOne({
                    refid: post._id,
                    refu: req.user.id
                }).exec();

                if (!dap) {
                    return result;
                }

                if (!dap.canGet) {
                    return result;
                }

                if (dap.isBanGet) {
                    return result;
                }
            }
        }
        result.push(post);
        return result;
    }, []);

    return res.json({
        "status": "success",
        "data": JSON.stringify(dpsr),
        "detail": `The operation is successfully`,
        ...ErrorTypes[200]
    });
};

const get = async(req, res, next) => {
    const schema = Joi.object({
        uid: Joi.string().required(),
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
            "detail": 'Unauthorized',
            ...ErrorTypes[401]
        });
    }

    const dp = await Post.findOne({
        _id: id
    }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `The operation encountered a problem while extracting the posts`,
            ...ErrorTypes[404]
        });
    }

    const duref = await User.findOne({
        _id: dp.uid
    }).exec();

    if (!duref) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'User not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canGet) {
        if (req.user.id !== dp.uid) {
            const dau = await Access.findOne({
                refid: dp.uid,
                refu: req.user.id
            }).exec();

            if (dau.isBanGet) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `This is a private account and you are not allowed to access it`,
                    ...ErrorTypes[403]
                });
            }

            if (duref.isPrivate) {
                if (!dau) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `This is a private account and you are not allowed to access it`,
                        ...ErrorTypes[403]
                    });
                }
                if (!dau.canGet) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `You are not allowed to get the post`,
                        ...ErrorTypes[403]
                    });
                }
            }
        }
    }

    return res.json({
        "status": "success",
        "data": dp.toJSON(),
        "detail": `The operation is successfully`,
        ...ErrorTypes[200]
    });
}

const nearest = async(req, res, next) => {
    const schema = Joi.object({
        coordinates: Joi.array().required(),
        skip: Joi.number().required(),
        limit: Joi.number().required()
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

    const { coordinates, skip, limit } = value;

    const dur = await User.findOne({
        _id: req.user.id
    }).exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": 'Unauthorized',
            ...ErrorTypes[401]
        });
    }

    const dps = await Post.find({
            $geoNear: {
                near: { type: "Point", coordinates },
                key: "location",
                distanceField: "dist.calculated",
                query: {}
            }
        })
        .sort({ updatedAt: -1 })
        .skip(skip)
        .limit(limit)
        .exec();

    if (!dps) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `The operation encountered a problem while extracting the posts`,
            ...ErrorTypes[404]
        });
    }

    const dpsr = dps.reduce(async(result, post) => {
        const resp = await result;
        if (!dur.canGet) {
            if (post.uid !== req.user.id) {
                const duref = await User.findOne({
                    _id: post.uid
                }).exec();

                if (!duref) {
                    return resp;
                }

                const dau = await Access.findOne({
                    refid: post.uid,
                    refu: req.user.id
                }).exec();

                if (dau.isBanGet) {
                    return resp;
                }

                if (duref.isPrivate) {
                    if (!dau) {
                        return resp;
                    }

                    if (!dau.canGet) {
                        return resp;
                    }
                }
            }
        }
        resp.push(post);
        return resp;
    }, Promise.resolve([]));

    return res.json({
        "status": "success",
        "data": JSON.stringify(await dpsr),
        "detail": `The operation is successfully`,
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
            "detail": 'Unauthorized',
            ...ErrorTypes[401]
        });
    }

    const dp = await Post.findOne({
        _id: id
    }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'The operation encountered a problem while extracting the post',
            ...ErrorTypes[404]
        });
    }

    const duref = await User.findOne({
        _id: dp.uid
    }).exec();

    if (!duref) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'User not found',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canPermote) {
        if (req.user.id !== dp.uid) {
            const dau = await Access.findOne({
                refid: dp.uid,
                refu: req.user.id
            }).exec();

            if (dau.isBanPermote) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `This is a private account and you are not allowed to access it`,
                    ...ErrorTypes[403]
                });
            }

            if (duref.isPrivate) {
                if (!dau) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `This is a private account and you are not allowed to access it`,
                        ...ErrorTypes[403]
                    });
                }

                if (!dau.canPermote) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `This is a private account and you are not allowed to access it`,
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

    if (dp.privacy.some(x => x === term)) {
        const rp = await Post.update({
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
            "detail": `Post permoted successfully`,
            ...ErrorTypes[200]
        });
    } else {
        const rp = await Post.update({
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
            "detail": `Post permoted successfully`,
            ...ErrorTypes[200]
        });
    }
}

const router = Router();

router.post(`/create`, verifyJWT(), create);
router.post(`/remove`, verifyJWT(), remove);
router.post(`/get`, verifyJWT(), get);
router.post(`/gets`, verifyJWT(), gets);
router.post(`/nearest`, verifyJWT(), nearest);
router.post(`/permote`, verifyJWT(), permote);

module.exports = router;