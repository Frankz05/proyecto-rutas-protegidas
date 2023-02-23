const { describe, it, before } = require('mocha')
const chai = require('chai')
const chaiHttp = require('chai-http')

const app = require('../../src/app')

chai.use(chaiHttp)

describe('Testing de la ruta protegidas de delete en /api/v1/users/:id', () => {
    it('Deberia generar un error 401 al no mandarle token', (done) => {
        chai.request(app)
            .delete('/api/v1/users/011b74d8-5881-4e53-a38d-cecfd38d1b32')
            .end((err, res) => {
                chai.assert.equal(res.status, 401)
                done()
            })
    })

})

describe('Testing de la ruta protegidas de delete en /api/v1/users/:id', () => {
    it('Deberia generar un error 401 al no mandarle token', (done) => {
        chai.request(app)
            .patch('/api/v1/users/011b74d8-5881-4e53-a38d-cecfd38d1b32')
            .end((err, res) => {
                chai.assert.equal(res.status, 401)
                done()
            })
    })
    
})
