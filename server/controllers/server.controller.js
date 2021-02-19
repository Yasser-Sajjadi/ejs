const { express, Router } = require('express'),
    Joi = require('joi'),
    verifyJWT = require("../middleware/authenticateJWT"), { ErrorTypes } = require("../middleware/error");

const info = (req, res, next) => {
    const today = new Date();

    return res.json({
        "status": "success",
        "data": {
            date: {
                today,
                day: today.getDay(),
                date: today.getDate,
                time: today.getTime(),
                fullYear: today.getFullYear,
                hours: today.getHours,
                milliseconds: today.getMilliseconds,
                seconds: today.getSeconds,
                minutes: today.getMinutes,
                month: today.getMonth
            }
        },
        "detail": `server time`,
        ...ErrorTypes[200]
    });
}

const router = Router();
router.post(`/info`, info);

module.exports = router;