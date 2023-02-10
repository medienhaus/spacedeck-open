"use strict";

var express = require('express');
var router = express.Router();

var config = require('config');
var crypto = require('crypto');
const db = require('../../models/db');


var passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy;

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  },
  function(username, password, done) {
    const email = username.toLowerCase();
    db.User.findOne({where: {email: email}})
        .error(err => {
            return done(err);
        })
    .then(user => {
      if (!user) {
        return done(null, false, { message: 'User not found.' });
      }
      return done(null, user);
    });
  }
));
passport.serializeUser(function(user, done) {
    done(null, user._id);
});

passport.deserializeUser(function(id, done) {
    db.User.findById(id).then(function(user) {
        done(null, user);
    }).error(err => {
        done(err);
    });
});
router.post('/', (req, res, next) => {
    passport.authenticate('local',
    (err, user, info) => {
        console.log('LOCALSTRATEGY@');
        if (err) {
            return next(err);
        }

        if (!user) {
            return res.redirect('/login?info=' + info);
        }

        req.logIn(user, function(err) {
            if (err) {
                return next(err);
            }
            crypto.randomBytes(48, function(ex, buf) {
            var token = buf.toString('hex');
    
            var session = {
                user_id: user._id,
                token: token,
                ip: req.ip,
                device: "web",
                created_at: new Date()
            };
    
            db.Session.create(session)
                .error(err => {
                    console.error("Error creating Session:",err);
                    res.sendStatus(500);
                })
                .then(() => {
                    var domain = (process.env.NODE_ENV == "production") ? new URL(config.get('endpoint')).hostname : req.headers.hostname;
                    res.cookie('sdsession', token, { domain: domain, httpOnly: true });
                    res.status(201).json(session);
                });
            });
            // res.status(201).json(user);
            // return res.redirect('/');
        });

    })(req, res, next);
});

module.exports = router;