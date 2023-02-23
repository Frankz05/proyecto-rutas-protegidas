const { describe, it } = require('mocha')
const { assert } = require('chai')

const {comparePassword, hashPassword} = require('../../src/utils/crypto')

describe('Testing de la utilidad hashPassword', () => {
    it('Deberia retornar una contraseña encriptada cuando pasamos root', (done) => {
        const response = hashPassword('root')
        assert.isNotEmpty(response)
        assert.notEqual(response, 'root')
        done()
    })
    it('Deberia retornar una contraseña encriptada cuando pasamos 1234', (done) => {
        const response = hashPassword('1234')
        assert.isNotEmpty(response)
        assert.notEqual(response, '1234')
        done()
    })
})

describe('Testing de la utilidad comparePassword', () => {

    it('Deberia retornar false en caso de que las credenciales sean incorrectas', (done) => {
        const response = comparePassword('1234', '$2b$10$Fpxk3hzdPmxCpO/Pe0eONu9kQ.yPOYDdCNXEH.DWckyjG4qvZCHi6')
        assert.equal(response, false)
        done()
    }) 
    
    it('Deberia retornar false en caso de que no pasemos nada', (done) => {
        const response = comparePassword('', '')
        assert.equal(response, false)
        done()
    })  

    it('Deberia retornar true en caso de que las credenciales sean correctas', (done) => {
        const response = comparePassword('root', '$2b$10$Fpxk3hzdPmxCpO/Pe0eONu9kQ.yPOYDdCNXEH.DWckyjG4qvZCHi6')
        assert.equal(response, true)
        done()
    })   
})



