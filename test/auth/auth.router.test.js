const { describe, it, before } = require('mocha')
const chai = require('chai')
const chaiHttp = require('chai-http')

const app = require('../../src/app')
const { createUsers, deleteUsers } = require('../seeders/users.seeders')

chai.use(chaiHttp)

before(() => {
    createUsers()
})



describe('Testing de la ruta /api/v1/auth/login', () => {
    it('Deberia generar un error 401 al no mandarle credenciales', (done) => {
        chai.request(app)
            .post('/api/v1/auth/login')
            .end((err, res) => {
                chai.assert.equal(res.status, 401)
                done()
            })
    })

    it('Deberia generar un error 401 al mandarle credenciales incorrectas', (done) => {
        chai.request(app)
            .post('/api/v1/auth/login')
            .set("content-type", "application/json")
            .send({email: "marquito@gmail.com", password: 'root'})
            .end((err, res) => {
                chai.assert.equal(res.status, 401)
                done()
            })
    })

    it('Deberia generar un estatus 200 al mandar credenciales correctas', (done) => {
        chai.request(app)
            .post('/api/v1/auth/login')
            .set("content-type", "application/json")
            .send({email: "marquito@gmail.com", password: 'root123'})
            .end((err, res) => {
                chai.assert.equal(res.status, 200)
                done()
            })
    })

})




