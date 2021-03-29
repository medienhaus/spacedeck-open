"use strict";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

const db = require('../../models/db');
var express = require('express');
var router = express.Router();
var config = require('config');
const usersHelper = require('../../helpers/users');


var passport = require('passport')
  , LdapStrategy = require('passport-ldapauth');

var opts = {
    usernameField: 'email',
    passwordField: 'password',
    server: {
        url: config.get("auth_ldap_server"),
        bindDN: config.get("auth_ldap_bind_dn"),
        bindCredentials: config.get("auth_ldap_bind_credentials"),
        searchBase: config.get("auth_ldap_search_base"),
        searchFilter: config.get("auth_ldap_search_filter"),
        searchAttributes: config.get("auth_ldap_search_attributes"),
        tlsOptions: {}
    }
};
if(config.has('auth_ldap_starttls')) {
    opts.server.tlsOptions.starttls = true;
    opts.server.rejectUnauthorized = false;
}
if(config.has('auth_ldap_tls_cert')) {
    opts.server.tlsOptions = {
        ca: [
            tfs.readFileSync(config.get("auth_ldap_tls_cert"))
        ]
    }
}

passport.use(new LdapStrategy(opts));

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    db.User.findOne({where: {nickname: user.uid}})
        .error(err => {
            return done(err);
        })
    .then(user => {
      if (!user) {
        return done(null, false, { message: 'User not found.' });
      }
      return done(null, user);
    });
});

router.post('/', (req, res, next) => {
    passport.authenticate('ldapauth',
    (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.status(400).json({"error": info.message});
            // return res.redirect('/login?info=' + info);
        }
        req.logIn(user, function(err) {
            if (err) {
                return next(err);
            }
            // var email = user.mailRoutingAddress.toLowerCase();
            var email = user[config.get('auth_ldap_mail_attribute')].toLowerCase();
            var nickname = user.uid;
            var password = "";
            var domain = (process.env.NODE_ENV == "production") ? new URL(config.get('endpoint')).hostname : req.headers.hostname;

            db.User.findAll({where: {email: email}})
            .then(users => {
            if (users.length == 0) {
                usersHelper.createUser(email, nickname, password, "en", "Home")
                .then((user) => {
                    usersHelper.createSession(user, req.ip)
                    .then((session) => {
                        res.cookie('sdsession', session.token, { domain: domain, httpOnly: true });
                        res.status(201).json(session);
                    }).catch((err) => {
                        res.status(400).json(err);
                    });
                }).catch((err) => {
                    res.status(500).json(err);
                }); 
            } else {
                usersHelper.createSession(users[0], req.ip)
                .then((session) => {
                    res.cookie('sdsession', session.token, { domain: domain, httpOnly: true });
                    res.status(201).json(session);
                }).catch((err) => {
                    res.status(500).json(err);
                });
                // res.status(400).json({"error":"user_email_already_used"});
            }
            });
            
            // res.status(201).json(user);
            // return res.redirect('/');
        });

    })(req, res, next);
});

router.delete('/current', function(req, res, next) {
    if (req.user) {
        req.logout();
      var token = req.cookies['sdsession'];
      db.Session.findOne({where: {token: token}})
        .then(session => {
          session.destroy();
        });
      var domain = (process.env.NODE_ENV == "production") ? new URL(config.get('endpoint')).hostname : req.headers.hostname;
      res.clearCookie('sdsession', { domain: domain });
      res.sendStatus(204);
    } else {
      res.sendStatus(404);
    }
  });
  

module.exports = router;