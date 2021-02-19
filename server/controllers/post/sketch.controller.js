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
        pid: Joi.string().required(),
        type: Joi.string().required(),
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

    const { pid, type, terms } = value;
    const dur = await User.findOne({ _id: req.user.id })
        .exec();

    if (!dur) {
        return res.status(401).json({
            "status": "error",
            "data": null,
            "detail": 'Unauthorized',
            ...ErrorTypes[401]
        });
    }

    // check post is exist
    const dp = await Post.findOne({
        _id: pid
    }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'The operation encountered a problem while extracting the post',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canCreate) {
        if (req.user.id !== dp.uid) {
            const dau = await Access.findOne({
                pid: dp.uid,
                uid: req.user.id
            }).exec();

            if (!dau) {
                const dap = await Access.findOne({
                    pid: dp._id,
                    uid: req.user.id
                }).exec();

                if (!dap) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `The reference does not belong to you`,
                        ...ErrorTypes[403]
                    });
                }

                if (!dap.canCreate) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `You are not allowed to create the sketch`,
                        ...ErrorTypes[403]
                    });
                }
            }

            if (!dau.canCreate) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `The reference does not belong to you`,
                    ...ErrorTypes[403]
                });
            }
        }
    }

    const dsk = await Sketch.create(new Sketch({
        pid,
        uid: req.user.id,
        type,
        privacy: terms.reduce((result, term) => {
            if (dur.acceptTerms.some(x => x === term)) {
                result.push(term);
            }
            return result;
        }, [])
    }));

    return res.json({
        "status": "success",
        "data": dsk.toJSON(),
        "detail": `creating new sketch is successfully`,
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

    // is authorized
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

    // check sketch is exist
    const dsk = await Sketch.findOne({
        _id: id
    }).exec();

    if (!dsk) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'The operation encountered a problem while extracting the sketch',
            ...ErrorTypes[404]
        });
    }

    // check post is exist
    const dp = await Post.findOne({
        _id: dsk.pid
    }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'The operation encountered a problem while extracting the post',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canRemove) {
        if (req.user.id !== dsk.uid) {
            if (req.user.id !== dp.uid) {
                const dau = await Access.findOne({
                    pid: dsk.uid,
                    uid: req.user.id
                }).exec();

                if (!dau) {
                    const dap = await Access.findOne({
                        pid: dp.uid,
                        uid: req.user.id
                    }).exec();

                    if (!dap) {
                        return res.status(403).json({
                            "status": "error",
                            "data": null,
                            "detail": `The reference does not belong to you`,
                            ...ErrorTypes[403]
                        });
                    }

                    if (!dap.canRemove) {
                        return res.status(403).json({
                            "status": "error",
                            "data": null,
                            "detail": `You are not allowed to remove the sketch`,
                            ...ErrorTypes[403]
                        });
                    }
                }

                if (!dau.canRemove) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `The reference does not belong to you`,
                        ...ErrorTypes[403]
                    });
                }
            }
        }
    }

    const rsk = await Sketch.findOneAndRemove({
        _id: id
    });

    if (!rsk) {
        return res.status(500).json({
            "status": "error",
            "data": null,
            "detail": `Updating has encountered problems`,
            ...ErrorTypes[500]
        });
    }

    return res.json({
        "status": "success",
        "data": rsk.toJSON(),
        "detail": `Removing sketch is successfully`,
        ...ErrorTypes[200]
    });
}

const gets = async(req, res, next) => {
    const schema = Joi.object({
        pid: Joi.number().required()
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

    const { pid } = value;

    // is authorized
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

    // check
    const dp = await Post.findOne({
        _id: pid
    }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'The operation encountered a problem while extracting the post',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canGet) {
        if (req.user.id !== dp.uid) {
            const dau = await Access.findOne({
                pid: dp.uid,
                uid: req.user.id
            }).exec();

            if (!dau) {
                const dap = await Access.findOne({
                    pid: dp._id,
                    uid: req.user.id
                }).exec();

                if (!dap) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `The reference does not belong to you`,
                        ...ErrorTypes[403]
                    });
                }

                if (!dap.canCreate) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `You are not allowed to create the sketch`,
                        ...ErrorTypes[403]
                    });
                }
            }

            if (!dau.canCreate) {
                return res.status(403).json({
                    "status": "error",
                    "data": null,
                    "detail": `The reference does not belong to you`,
                    ...ErrorTypes[403]
                });
            }
        }
    }

    const dss = await Sketch.find({
        pid
    }).sort({ updatedAt: -1 }).exec();

    if (!dss) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": `The operation encountered a problem while extracting the sketchs`,
            ...ErrorTypes[404]
        });
    }

    const dsrs = dss.reduce(async(result, sketch) => {
        if (!dur.canGet) {
            if (sketch.uid !== req.user.id) {
                if (sketch.isPrivate) {
                    const access = await Access.findOne({
                        pid: sketch._id,
                        uid: req.user.id
                    }).exec();

                    if (!access) {
                        return result;
                    }

                    if (!access.canGet) {
                        return result;
                    }
                }
            }
        }
        result.push(sketch);
        return result;
    }, []);

    return res.json({
        "status": "success",
        "data": JSON.stringify(await dsrs),
        "detail": `Getting sketchs is successfully`,
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

    // is authorized
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

    // check
    const dsk = await Sketch.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!dsk) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'The operation encountered a problem while extracting the sketch',
            ...ErrorTypes[404]
        });
    }

    const dp = await Post.findOne({
        _id: dsk.uid
    }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'The operation encountered a problem while extracting the post',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canGet) {
        if (req.user.id !== dsk.uid) {
            if (req.user.id !== dp.uid) {
                const dau = await Access.findOne({
                    pid: dp.uid,
                    uid: req.user.id
                }).exec();

                if (!dau) {
                    const dap = await Access.findOne({
                        pid: dp.uid,
                        uid: req.user.id
                    }).exec();

                    if (!dap) {
                        return res.status(403).json({
                            "status": "error",
                            "data": null,
                            "detail": `The reference does not belong to you`,
                            ...ErrorTypes[403]
                        });
                    }

                    if (!dap.canGet) {
                        return res.status(403).json({
                            "status": "error",
                            "data": null,
                            "detail": `You are not allowed to get the sketch`,
                            ...ErrorTypes[403]
                        });
                    }
                }

                if (dau && !dau.canGet) {
                    return res.status(403).json({
                        "status": "error",
                        "data": null,
                        "detail": `The reference does not belong to you`,
                        ...ErrorTypes[403]
                    });
                }
            }
        }
    }

    return res.json({
        "status": "success",
        "data": dsk.toJSON(),
        "detail": `Getting sketch is successfuly`,
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

    // check
    const dsk = await Sketch.findOne({
        _id: id
    }).sort({ updatedAt: -1 }).exec();

    if (!dsk) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'The operation encountered a problem while extracting the sketch',
            ...ErrorTypes[404]
        });
    }

    const dp = await Post.findOne({
        _id: dsk.uid
    }).exec();

    if (!dp) {
        return res.status(404).json({
            "status": "error",
            "data": null,
            "detail": 'The operation encountered a problem while extracting the post',
            ...ErrorTypes[404]
        });
    }

    if (!dur.canPermote) {
        if (req.user.id !== dsk.uid) {
            if (req.user.id !== dp.uid) {
                const dau = await Access.findOne({
                    pid: dsk.uid,
                    uid: req.user.id
                }).exec();

                if (!dau) {
                    const dap = await Access.findOne({
                        pid: dp.uid,
                        uid: req.user.id
                    }).exec();

                    if (!dap) {
                        return res.status(403).json({
                            message: 'The reference does not belong to you'
                        });
                    }

                    if (!dap.canPermote) {
                        return res.status(403).json({
                            message: 'You are not allowed to delete the reference'
                        });
                    }
                }

                if (!dau.canPermote) {
                    return res.status(403).json({
                        message: 'You are not allowed to delete the reference'
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

    if (dsk.privacy.some(x => x === term)) {
        const dsr = await Sketch.update({
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
            "data": dsr.toJSON(),
            "detail": `Password permoted successfully`,
            ...ErrorTypes[200]
        });
    } else {
        const dsr = await Sketch.update({
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
            "data": dsr.toJSON(),
            "detail": `Password permoted successfully`,
            ...ErrorTypes[200]
        });
    }
}

const router = Router();

router.post(`/create`, verifyJWT(), create);
router.post(`/remove`, verifyJWT(), remove);
router.post(`/get`, verifyJWT(), get);
router.post(`/gets`, verifyJWT(), gets);
router.post(`/permote`, verifyJWT(), permote);

module.exports = router;