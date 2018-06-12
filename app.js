const express = require('express');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const errorhandler = require('errorhandler');
const session = require('express-session');
const app = express();
const config = require('config');
const cors = require('cors');
const util = require('util');
const logger = require('dvp-common-lite/LogHandler/CommonLogHandler.js').logger;


app.set('view engine', 'ejs');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'keyboard cat', resave: true, saveUninitialized: true}));
app.use(passport.initialize());
app.use(passport.session());
app.use(cookieParser());
app.use(errorhandler({ dumpExceptions: true, showStack: true }));
app.use(cors());


const port = config.Host.port || 3000;
const host = config.Host.vdomain || 'localhost';


app.listen(port, function () {

    logger.info("DVP-IdentityService.main Server listening at %d", port);

});