//? Dependencies
const express = require('express')

//? File imports
const config = require('../config')
const { error, success } =require('./utils/responses.handler')
const db = require('./utils/database')
//? Router Imports
const userRouter = require('./users/users.router')
const authRouter = require('./auth/auth.router')

//? Initial Configs
const app = express()
app.use(express.json())
app.use(express.urlencoded({extended: false}))
//? Database Configs

db.authenticate()
    .then(() => console.log('Database Authenticated'))
    .catch(err => console.log(err))

db.sync()
    .then(() => console.log('Database Synced'))
    .catch(err => console.log(err))

//? Routes
app.get('/', (req, res) => {
    success({
        res,
        status: 200,
        data: {
            users: `${config.api.host}/api/v1/users`,
            auth: `${config.api.host}/api/v1/auth`
        }
    })
})

app.use('/api/v1/users', userRouter)
app.use('/api/v1/auth', authRouter)

//? 404 Error Handler
app.use('*', (req, res) => {
    error({
        res,
        status: 404,
        message: 'Page Not Found'
    })
})

app.listen(config.api.port, () => {
    console.log(`Server started succesfully on ${config.api.host}`)
})

module.exports = app