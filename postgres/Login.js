const dbmodel = require("dvp-dbmodels");
let redisClient = require("../helpers/RedisHelper");
let PublishToQueue = require('./Worker').PublishToQueue;
var bcrypt = require('bcryptjs');
let moment = require('moment');
let accessToken = require ('dvp-mongomodels/model/AccessToken');


function comparePassword(password, done) {
    bcrypt.compare(password, this.password, function(err, isMatch) {
        done(err, isMatch);
    });
};

function GetScopes(user, account, claims){


    let payload = {};
    payload.context = {};
    payload.scope = [];

    if(claims) {
        let index = claims.indexOf("profile_contacts");

        if (index > -1) {
            payload.context.phonenumber = user.phoneNumber;
            payload.context.email = user.email;
            payload.context.othercontacts = user.contacts;

            claims.splice(index, 1);
        }


        let index = claims.indexOf("app_meta");

        if (index > -1) {
            payload.context.appmeta = user.app_meta;
            claims.splice(index, 1);
        }


        let index = claims.indexOf("user_scopes");

        if (index > -1) {
            payload.context.userscopes = user.user_scopes;
            claims.splice(index, 1);
        }

        let index = claims.indexOf("client_scopes");

        if (index > -1) {
            payload.context.clientscopes = user.client_scopes;
            claims.splice(index, 1);
        }


        let index = claims.indexOf("resourceid");

        if (index > -1) {
            payload.context.resourceid = user.IdentityAccount.resource_id;
            claims.splice(index, 1);
        }


        let profileClaimsFound = claims.filter(function (item, index) {

            return item.startsWith('profile_');
        })

        profileClaimsFound.forEach(function (value) {


            let arr = value.split("_");
            if (arr.length > 1) {

                let action = arr[0];
                let resource = arr[1];

                if(action == "profile"){


                    if(resource == "password"){

                        payload.context[resource] = undefined;
                    }
                    else{

                        payload.context[resource] = user[resource];
                    }

                }

            }});


        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        let index = claims.indexOf("all_all");

        if (index > -1) {
            user.user_scopes.forEach(function (item){
                let actionObj = {};
                actionObj.resource = item.scope;
                actionObj.actions = [];

                if(item.read){
                    actionObj.actions.push("read");
                }

                if(item.write){

                    actionObj.actions.push("write");
                }

                if(item.delete){

                    actionObj.actions.push("delete");
                }
                payload.scope.push(actionObj);
            });

        }else {

            claims.forEach(function (value) {


                let arr = value.split("_");
                if (arr.length > 1) {

                    let action = arr[0];
                    let resource = arr[1];


                    let scopeFound = user.user_scopes.filter(function (item) {
                        return item.scope == resource;
                    })


                    if (scopeFound.length > 0) {

                        let myscope = {};
                        myscope.resource = scopeFound[0].scope;
                        myscope.actions = [];

                        if (action == "read") {

                            let actionArray = [];
                            if (scopeFound[0].read) {

                                actionArray.push("read");

                            }

                            myscope.actions = myscope.actions.concat(actionArray);


                        }
                        else if (action == "write") {


                            let actionArray = [];
                            if (scopeFound[0].read) {

                                actionArray.push("read");

                            }

                            if (scopeFound[0].write) {

                                actionArray.push("write");

                            }


                            myscope.actions = myscope.actions.concat(actionArray);

                        }
                        else if (action == "all") {


                            let actionArray = [];
                            if (scopeFound[0].read) {

                                actionArray.push("read");

                            }

                            if (scopeFound[0].write) {

                                actionArray.push("write");

                            }


                            if (scopeFound[0].delete) {

                                actionArray.push("delete");

                            }

                            myscope.actions = myscope.actions.concat(actionArray);

                        }

                        payload.scope.push(myscope);
                    }
                }
            });
        }
    }
    return payload;

}

function GetJWT(user, account, scopesx, client_id, type, req, done){

    let jti = uuid.v4();
    let secret = uuid.v4();
    let expin  = moment().add(7, 'days').unix();
    let redisKey = "token:iss:"+user.username+":"+jti;
    let tokenMap = "token:iss:"+user.username+":*";

    if(commonsignature === true || commonsignature === "true"){

        let payload = {};

        secret = jti;
        payload.iss = user.name;
        payload.jti = jti;
        payload.sub = "Access client";
        payload.exp = expin;
        payload.tenant = user.Organizations.tenantId;
        payload.company = user.Organizations.id;
        //payload.aud = client.name;

        if (user.companyName)
            payload.companyName = user.Organizations.name;

        let scopes = GetScopes(user, account, scopesx);
        payload.context = scopes.context;
        payload.scope = scopes.scope;
        let token = jwt.sign(payload, secret);

        let accesstoken = accessToken({

            userId: user._id,
            clientId: client_id,
            jti: jti,
            Agent: req.headers['user-agent'],
            Location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
            scope: scopesx,
            expirationDate: expin,
            type: type
        });

        accesstoken.save(function (err, accesstoken) {
            if (err) {

                return done(err, false, undefined);
            }
            return done(undefined, true, token);
        });

    }else {


        if ((multilogin ===false || multilogin === "false") || (user.multi_login != undefined && user.multi_login === false)) {

            redisClient.keys(tokenMap, function (err, res) {

                if (Array.isArray(res)) {
                    res.forEach(function (item) {
                        //let delRedisKey = "token:iss:"+user.username+":"+item;
                        redisClient.del(item, function (err, res) {
                            logger.info("JTI deleted -> ", item);
                        })
                    })
                }

                redisClient.set(redisKey, secret, function (err, res) {

                    if (!err) {
                        redisClient.expireat(redisKey, expin);

                        let payload = {};
                        payload.iss = user.username;
                        payload.jti = jti;
                        payload.sub = "Access client";
                        payload.exp = expin;
                        payload.tenant = user.tenant;
                        payload.company = user.company;

                        if (user.companyName)
                            payload.companyName = user.companyName;
                        //payload.aud = client.name;

                        let scopes = GetScopes(user, scopesx);
                        payload.context = scopes.context;
                        payload.scope = scopes.scope;
                        let token = jwt.sign(payload, secret);


                        let accesstoken = accessToken({

                            userId: user._id,
                            clientId: client_id,
                            jti: jti,
                            Agent: req.headers['user-agent'],
                            Location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                            scope: scopesx,
                            expirationDate: expin,
                            type: type
                        });

                        accesstoken.save(function (err, accesstoken) {
                            if (err) {

                                return done(err, false, undefined);
                            }
                            return done(undefined, true, token);
                        });
                    } else {

                        return done(err, false, undefined);
                    }

                });

            });
        } else {

            redisClient.set(redisKey, secret, function (err, res) {

                if (!err) {


                    redisClient.expireat(redisKey, expin);

                    let payload = {};
                    payload.iss = user.username;
                    payload.jti = jti;
                    payload.sub = "Access client";
                    payload.exp = expin;
                    payload.tenant = user.tenant;
                    payload.company = user.company;
                    //payload.aud = client.name;

                    if (user.companyName)
                        payload.companyName = user.companyName;

                    let scopes = GetScopes(user, scopesx);
                    payload.context = scopes.context;
                    payload.scope = scopes.scope;
                    let token = jwt.sign(payload, secret);


                    let accesstoken = accessToken({


                        userId: user._id,
                        clientId: client_id,
                        jti: jti,
                        Agent: req.headers['user-agent'],
                        Location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                        scope: scopesx,
                        expirationDate: expin,
                        type: type
                    });

                    accesstoken.save(function (err, accesstoken) {
                        if (err) {

                            return done(err, false, undefined);
                        }
                        return done(undefined, true, token);
                    });
                } else {

                    return done(err, false, undefined);
                }

            });
        }
    }
}

class PostgresLogin{

    constructor(){}

    Login(req, res) {


        dbmodel.Identity.find({
            where: [
                {
                    'username': req.body.userName
                }],
            include: [
                {
                    model: dbmodel.Organization, as: 'Organizations',
                    through: {
                        attributes: ['joined', 'active', 'verified', 'multi_login', 'allow_outbound', 'auth_mechanism', 'roles', 'id']
                        //include:[{model: dbmodel.SipUACEndpoint, as: 'SIPAccount',}, {model: dbmodel.ResResource, as: 'Resource'}]
                    },
                    where: [{name: req.body.companyName}]
                }
            ]
        }).then(function (user) {

            dbmodel.IdentityAccount.find({
                where: [{id: user.Organizations.IdentityAccount.id}],
                include: [
                    {model: dbmodel.SipUACEndpoint, as: "SIPAccount", include: [
                        {
                            model: dbmodel.CloudEndUser,
                            as: "CloudEndUser"
                        },
                        {
                            model: dbmodel.Extension,
                            as: "Extension"
                        }]},
                    {model: dbmodel.ResResource, as: "Resource" }]
            }).then(function(identityAccount){




                if (!user) {
                    return res.status(401).send({message: 'Invalid email and/or password'});
                }

                if (user && !user.active) {
                    return res.status(401).send({message: 'User account deactivated, Please activate your account before login'});
                }

                if (!user.Organizations) {
                    return res.status(401).send({message: 'Invalid organization name'});
                }

                if (user.Organizations.enable === false) {
                    return res.status(449).send({message: 'Activate your organization before login'});
                }

                if (!user.IdentityAccount) {
                    return res.status(401).send({message: 'Invalid user account'});
                }

                if ((config.auth.login_verification === true || config.auth.login_verification === 'true') && (user.IdentityAccount.verified != true || user.IdentityAccount.active != true )) {
                    return res.status(401).send({message: 'User account is not active'});
                }

                logger.info(`config.auth.login_verification --> ${ config.auth.login_verification + (config.auth.login_verification === true) } user.verified ---> ${user.IdentityAccount.verified + (user.IdentityAccount.verified === false) }  result -->
                ${((config.auth.login_verification == true) && (user.IdentityAccount.verified == false))}`);


                if ((config.auth.login_verification === true || config.auth.login_verification === 'true') && (user.IdentityAccount.verified === false)) {


                    crypto.randomBytes(20, function (err, buf) {
                        let token = buf.toString('hex');
                        let url = `${config.auth.ui_host}#/activate/${token}`;

                        redisClient.set("activate" + ":" + token, user._id, function (err, val) {
                            if (err) {

                                res.status(404).send({message: 'Create activation token failed'});

                            } else {

                                redisClient.expireat("activate" + ":" + token, parseInt((+new Date) / 1000) + 86400);
                                let sendObj = {
                                    "company": config.Tenant.activeCompany,
                                    "tenant": config.Tenant.activeTenant
                                };

                                sendObj.to = user.email.contact;
                                sendObj.from = "no-reply";
                                sendObj.template = "By-User Registration Confirmation";
                                sendObj.Parameters = {
                                    username: user.username,
                                    created_at: new Date(),
                                    url: url
                                }

                                PublishToQueue("EMAILOUT", sendObj)
                                return res.status(449).send({message: 'Activate your account before login'});
                            }
                        });

                    });
                } else {

                    comparePassword(req.body.password, function (err, isMatch) {
                        if (!isMatch) {
                            return res.status(401).send({message: 'Invalid email and/or password'});
                        }

                        let claims_arr = ["all_all"];
                        if (req.body.scope && util.isArray(req.body.scope) && req.body.scope.length > 0) {

                            claims_arr = req.body.scope;
                        }


                        dbmodel.Console.findOne({where: [{name: req.body.console}], include: [
                            {
                                model: dbmodel.UserRoles, as: 'UserRoles',
                                through: {
                                    attributes: [],
                                }
                            }
                        ]}).then(function (console) {

                            if (!console) {

                                return res.status(449).send({message: 'Request console is not valid ...'});
                            } else {


                                if (console.name == "OPERATOR_CONSOLE") {


                                    let bill_token_key = config.Tenant.activeTenant + "_BILL_TOKEN";
                                    let Hash_token_key = config.Tenant.activeTenant + "_BILL_HASH_TOKEN";


                                    logger.info("The bill token key is " + bill_token_key);
                                    logger.info("The hash token key is " + Hash_token_key);


                                    redisClient.get(bill_token_key, function (err, reply) {

                                        if (!err && reply) {

                                            let bill_token = reply;

                                            logger.debug("The bill token is " + reply)


                                            redisClient.get(Hash_token_key, function (err, reply) {

                                                if (!err && reply) {


                                                    let hash_token = reply;

                                                    logger.debug("The hash token is " + reply)

                                                    if (bill_token == Encrypt(hash_token, 'DuoS123412341234')) {

                                                        if (console.UserRoles && user.IdentityAccount
                                                            && user.IdentityAccount.roles && Array.isArray(console.UserRoles)
                                                            && console.UserRoles.indexOf(user.IdentityAccount.roles) >= 0) {

                                                            GetJWT(user, identityAccount, claims_arr, req.body.clientID, 'password', req, function (err, isSuccess, token) {

                                                                if (token) {
                                                                    return res.send({
                                                                        state: 'login',
                                                                        token: token
                                                                    });
                                                                } else {
                                                                    return res.status(401).send({message: 'Invalid email and/or password'});
                                                                }
                                                            });
                                                        } else {

                                                            return res.status(449).send({message: 'User console request is invalid'});
                                                        }

                                                    } else {

                                                        return res.status(449).send({message: 'Bill token is not match'});
                                                    }

                                                } else {

                                                    logger.error("Hash token failed", err);
                                                    return res.status(449).send({message: 'Hash token is not found'});
                                                }
                                            });
                                        } else {

                                            logger.error("Bill token failed ", err);
                                            return res.status(449).send({message: 'Bill token is not found'});
                                        }
                                    });


                                } else {

                                    if (console.UserRoles && user.IdentityAccount
                                        && user.IdentityAccount.roles && Array.isArray(console.UserRoles)
                                        && console.UserRoles.indexOf(user.IdentityAccount.roles) >= 0) {

                                        GetJWT(user, claims_arr, req.body.clientID, 'password', req, function (err, isSuccess, token) {

                                            if (token) {
                                                return res.send({state: 'login', token: token});
                                            } else {
                                                return res.status(401).send({message: 'Invalid email and/or password'});
                                            }
                                        });
                                    } else {

                                        return res.status(449).send({message: 'User console request is invalid'});
                                    }

                                }
                            }




                        }).catch(function (err) {
                            return res.status(449).send({message: 'Request console is not valid ...'});
                        });
                    });

                }




            }).catch(function(err){

                return res.status(449).send({message: 'Internal server Error'});

            });

        }).catch(function (err) {

            return res.status(449).send({message: 'Internal server Error'});
        });


    };

    Validation(req, res) {

        return res.status(449).send({message: 'This method is implemented'});
    };

    SignUP(req, res) {

        return res.status(449).send({message: 'This method is implemented'});
    };

    Google(req, res) {
        return res.status(449).send({message: 'This method is implemented'});
    };

    GitHub(req, res) {
        return res.status(449).send({message: 'This method is implemented'});
    };

    Facebook(req, res) {
        return res.status(449).send({message: 'This method is implemented'});
    };

    ForgetPassword(req, res){
        return res.status(449).send({message: 'This method is implemented'});
    };

    ForgetPasswordToken(req, res){
        return res.status(449).send({message: 'This method is implemented'});

    };

    ResetPassword(req, res){
        return res.status(449).send({message: 'This method is implemented'});
    };

    ActivateAccount(req, res){
        return res.status(449).send({message: 'This method is implemented'});
    };

    CheckToken(req, res) {
        return res.status(449).send({message: 'This method is implemented'});
    };

    Attachments(req,res){
        return res.status(449).send({message: 'This method is implemented'});
    }

}

module.exports = PostgresLogin;