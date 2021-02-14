"use strict";

var express = require('express');
var router = express.Router();

// var config = require('config');
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

            return res.redirect('/');
        });

    })(req, res, next);
});

module.exports = router;