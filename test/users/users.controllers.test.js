const { assert } = require('chai')
const { it, describe } = require('mocha')

const { findUserById } = require('../../src/users/users.controllers')

describe('Testing de creacion de usuario con contraseña encriptada', () => {
    it('Deberia retornar el nuevo usuario con la contraseña root encriptada', (done) => {
        findUserById('685603b5-9ba8-4062-8ade-893ee77934e9')
        .then(data => {
            assert.notEqual(data.password, 'root')
            done()
        })
        .catch(done)
    })
    it('Deberia retornar el nuevo usuario con la contraseña 1234 encriptada', (done) => {
        findUserById('011b74d8-5881-4e53-a38d-cecfd38d1b32')
        .then(data => {
            assert.notEqual(data.password, '1234')
            done()
        })
        .catch(done)
    })
})


