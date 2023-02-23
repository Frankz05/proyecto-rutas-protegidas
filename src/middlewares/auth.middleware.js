const {ExtractJwt, Strategy} = require('passport-jwt')
const passport = require('passport')
require('dotenv').config()

const {findUserById} = require('../users/users.controllers')

const passportConfig = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
}

passport.use(new Strategy(passportConfig, (tokenDecoded, done) => {
    findUserById(tokenDecoded.id)
        .then(data => {
            if(data){
                done(null, tokenDecoded)
            } else {
                done(null, false, {message: 'Token Incorrect'})
            }
        })
        .catch(err => {
            done(err, false)
        })
}))

module.exports = passport.authenticate('jwt', {session: false})