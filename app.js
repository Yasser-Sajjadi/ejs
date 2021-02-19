// require('rootpath')();
const express = require("express");
const winston = require("winston");
const expressWinston = require("express-winston");
const cors = require("cors");
const bodyParser = require("body-parser");
const expressLayouts = require("express-ejs-layouts");
const cookieParser = require("cookie-parser");
const path = require("path");
const config = require("./server/config.json");
const mongoose = require("mongoose");
const { errorHandler } = require('./server/middleware/error');

// Server
mongoose.connect(process.env.MONGODB_URI || config.connectionString, {
    useCreateIndex: true,
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false
});
mongoose.Promise = global.Promise;

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // for parsing application/json
app.use(cookieParser());

// allow cors requests from any origin and with credentials
app.use(cors({ origin: (origin, callback) => callback(null, true), credentials: true }));

// api routes
app.use('/api/users', require("./server/controllers/user/user.controller"));
app.use('/api/passwords', require("./server/controllers/user/password.controller"));
app.use('/api/posts', require("./server/controllers/post/post.controller"));
app.use('/api/sketchs', require("./server/controllers/post/sketch.controller"));
app.use('/api/emails', require("./server/controllers/user/email.controller"));
app.use('/api/mobiles', require("./server/controllers/user/mobile.controller"));
app.use('/api/aliases', require("./server/controllers/user/alias.controller"));
app.use('/api/server', require("./server/controllers/server.controller"));

// Static Files
app.use('/assets', express.static(path.join(__dirname, '/app/assets')));
app.use('/assets/modules/', express.static(path.join(__dirname, '/node_modules')));

app.set('views', path.join(__dirname, '/app'));
app.set('layouts', path.join(__dirname, '/app/layouts'));
app.set('components', path.join(__dirname, '/app/components'));

// Set Templating Engine
app.use(expressLayouts)
app.set('layout', 'layouts/device-viewport')

app.set('view engine', 'ejs')
app.set("layout extractScripts", true)

// Routes

app.get('/app.css', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/app.css'));
});

app.get('/app.js', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/app.js'));
});

app.get('/app', (req, res) => {
    res.render('app', {
        title: 'Home Page',
        extractScripts: true
    });
})

app.get('/sign-up.css', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/sign-up/sign-up.css'));
});

app.get('/sign-up.js', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/sign-up/sign-up.js'));
});

app.get('/sign-up', (req, res) => {
    res.render('sign-up/sign-up', {
        title: 'Sign Up Page',
        extractScripts: true
    });
});

app.get('/sign-in.css', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/sign-in/sign-in.css'));
});

app.get('/sign-in.js', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/sign-in/sign-in.js'));
});

app.get('/sign-in', (req, res) => {
    res.render('sign-in/sign-in', {
        title: 'Sign In Page',
        extractScripts: true
    });
});

app.get('/forgot.css', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/forgot/forgot.css'));
});

app.get('/forgot.js', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/forgot/forgot.js'));
});

app.get('/forgot', (req, res) => {
    res.render('forgot/forgot', {
        title: 'Forgot Page',
        extractScripts: true
    });
});

app.get('/about.css', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/about/about.css'));
});

app.get('/about.js', (req, res) => {
    res.sendFile(path.join(__dirname, '/app/about/about.js'));
});

app.get('/about', (req, res) => {
    res.render('about/about', {
        title: 'About Page',
        layout: 'layouts/sidebar',
        extractScripts: true
    });
});

// global error handler
app.use(errorHandler);

// start server
const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 3000;
app.listen(port, function() {
    console.log('Server listening on port ' + port);
});