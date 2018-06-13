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
const site = require('./sites');
const oauth2 = require('./mongo/oauth2');
var jwt = require('restify-jwt');

var secret = require('dvp-common/Authentication/Secret.js');
var authorization = require('dvp-common/Authentication/Authorization.js');



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
const model = config.Host.model || "mongo";


app.listen(port, function () {

    logger.info("DVP-IdentityService.main Server listening at %d", port);

});

let LoginHandlerFactory = require('./LoginHandlerFactory')

const factory = new LoginHandlerFactory();
const Login = factory.FactoryMethod(model);


app.get('/', site.index);
app.get('/login', site.loginForm);
app.post('/login', site.login);
app.get('/logout', site.logout);
app.get('/account', site.account);


app.get('/oauth/authorize', oauth2.authorization);
app.get('/dialog/authorize', oauth2.authorization);
app.post('/dialog/authorize/decision', oauth2.decision);
app.post('/oauth/token', oauth2.token);
app.delete('/oauth/token/revoke/:jti', jwt({secret: secret.Secret}), oauth2.revoketoken);


app.post('/auth/login', Login.Login);
app.post('/auth/verify', Login.Validation);
app.post('/auth/signup', Login.SignUP);
app.post('/auth/forget', Login.ForgetPassword);
app.post('/auth/forget/token', Login.ForgetPasswordToken);
app.post('/auth/reset/:token', Login.ResetPassword);
app.get('/auth/token/:token/exists', Login.CheckToken);
app.get('/auth/activate/:token', Login.ActivateAccount);
app.post('/auth/attachments', Login.Attachments);



app.post('/auth/google', Login.Google);
app.post('/auth/github', Login.GitHub);
app.post('/auth/facebook',Login.Facebook);

const dbmodel = require("dvp-dbmodels");
dbmodel.Identity.find({
    where: [
        {
            'username': 'Pawan'
        }],
    include: [
        {
            model: dbmodel.Organization, as: 'Organizations',
            through: {
                attributes: ['id','joined', 'active', 'verified', 'multi_login', 'allow_outbound', 'auth_mechanism', 'roles']
            }
        }
    ]
}).then(function (user) {
    console.log(user);
}).catch(function(err){
    console.log(err);
});


