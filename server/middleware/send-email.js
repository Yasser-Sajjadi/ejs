"use strict";
const nodemailer = require("nodemailer");
const config = require("../config.json");

module.exports = async(to, subject, html, from) => {
    const transporter = nodemailer.createTransport(config.smtpOptions);
    await transporter.sendMail({ from: from ? from : config.emailFrom, to, subject, html });
    console.log({ to, text });
}