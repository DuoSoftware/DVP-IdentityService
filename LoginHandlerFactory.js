
let Login = require("./Login");
let MongoLogin = require("./mongo/Login")


class LoginHandlerFactory{

    constructor(){

    }

    FactoryMethod(type){
        let login = new Login();

        switch(type){

            case 'mongo':
                login = new MongoLogin();
                break;
            case 'pgsql':
                break;
        }

        return login;
    }


}

module.exports = LoginHandlerFactory;