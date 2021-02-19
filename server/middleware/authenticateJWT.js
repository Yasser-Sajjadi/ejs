const expressJwt = require('express-jwt');
const config = require('../config.json');
const jwt = require("jsonwebtoken");

const User = require("../models/user/user.model");
const RefreshToken = require("../models/user/refresh-token.model");


module.exports = () => {
    return [
        // authenticate JWT token and attach user to request object (req.user)
        (req, res, next) => {
            // Gather the jwt access token from the request header
            const authHeader = req.headers['authorization']
            const token = authHeader && authHeader.split(' ')[1]
            if (token == null) {
                // if there isn't any token
                return res.sendStatus(401)
            }

            jwt.verify(token, config.secret, (err, user) => {
                if (err) {
                    return res.sendStatus(403);
                }
                req.user = user;
                next();
            });
        },

        // authorize based on user role
        async(req, res, next) => {
            const user = await User.findById(req.user.id);
            const refreshTokens = await RefreshToken.find({ user: user.id });

            if (!user) {
                // user no longer exists or role not authorized
                return res.status(401).json({ message: 'Unauthorized' });
            }

            // authentication and authorization successful
            req.user.role = user.role;
            req.user.ownsToken = token => !!refreshTokens.find(x => x.token === token);
            next();
        }
    ];
};