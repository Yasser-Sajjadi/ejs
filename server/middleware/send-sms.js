"use strict";
const nodemailer = require("nodemailer");
const config = require("../config.json");

module.exports = async(to, text) => {
    /*const transporter = nodemailer.createTransport(config.smtpOptions);
    await transporter.sendMail({ to, text });*/
    console.log({ to, text });
}