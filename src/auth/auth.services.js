const checkUserCredentials = require('./auth.controllers')
const response = require('../utils/responses.handler')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const postLogin = (req, res) => {
    const {email, password} = req.body

    checkUserCredentials(email, password)
        .then(data => {
            if(data){
                const token = jwt.sign({
                    id: data.id,
                    email: data.email,
                    firstName: data.firstName
                }, 'academlo', {
                    expiresIn: '1d'
                })

                response.success({
                    res,
                    status: 200,
                    message: 'Correct Credentials!',
                    data: token
                })
            } else {
                response.error({
                    res,
                    status: 401,
                    message: 'Invalid Credentials'
                })
            }
        })
        .catch(err => {
            response.error({
                res,
                status: 400,
                message: 'Something bad'
            })
        })
}

module.exports = postLogin