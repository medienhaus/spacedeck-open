"use strict";

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../models/db');
const uuidv4 = require('uuid/v4');

var createUser = function(email, nickname, password, locale, homeFolderName) {
    return new Promise((resolve, reject) => {
        bcrypt.genSalt(10, function(err, salt) {
            bcrypt.hash(password, salt, function(err, hash) {
            crypto.randomBytes(16, function(ex, buf) {
                var token = buf.toString('hex');
        
                var u = {
                _id: uuidv4(),
                email: email,
                account_type: "email",
                nickname: nickname,
                password_hash: hash,
                prefs_language: locale,
                confirmation_token: token
                };
        
                db.User.create(u)
                .error(err => {
                    reject(err);
                })
                .then(u => {
                    var homeFolder = {
                    _id: uuidv4(),
                    name: homeFolderName,
                    space_type: "folder",
                    creator_id: u._id
                    };
                    db.Space.create(homeFolder)
                    .error(err => {
                        reject(err);
                        // res.sendStatus(400);
                    })
                    .then(homeFolder => {
                        u.home_folder_id = homeFolder._id;
                        u.save()
                        .then(() => {
                            // home folder created,
                            // auto accept pending invites
                            db.Membership.update({
                            "state": "active"
                            }, {
                            where: {
                                "email_invited": u.email,
                                "state": "pending"
                            }
                            });
                            resolve(u)
                        })
                        .error(err => {
                            reject(err);
                        });
                    })
                });
            });
            });
        });
    });
};
var createSession = function(user, ip){
    return new Promise((resolve, reject) => {
        crypto.randomBytes(48, function(ex, buf) {
        var token = buf.toString('hex');
        var session = {
            user_id: user._id,
            token: token,
            ip: ip,
            device: "web",
            created_at: new Date()
        };

        db.Session.create(session)
            .error(err => {
                console.error("Error creating Session:", err);
                reject(err);
                // res.sendStatus(500);
            })
            .then(() => {
                resolve(session)
                // var domain = (process.env.NODE_ENV == "production") ? new URL(config.get('endpoint')).hostname : req.headers.hostname;
                // res.cookie('sdsession', token, { domain: domain, httpOnly: true });
                // res.status(201).json(session);
            });
        });
    });
}
module.exports = {
    createUser,
    createSession
}