const Users = require('../../src/models/users.models')
const { hashPassword } = require('../../src/utils/crypto')
const userBases = [
    {
        id: 'de69c924-03f1-4b6e-93ad-8fe17ec1121d',
        firstName: 'Sahid',
        lastName: 'Kick',
        email: 'sahid123@gmail.com',
        password: hashPassword('root123')
    },
    {
        id: '280ca98b-3c7e-4a3c-9a5a-0089aca1972f',
        firstName: 'Marco',
        lastName: 'Gonzalez',
        email: 'marquito@gmail.com',
        password: hashPassword('root123')
    },
    {
        id: '55d7935f-3bb3-4133-be34-de05a22fdd47',
        firstName: 'Valeria',
        lastName: 'Nolasco',
        email: 'vale@gmail.com',
        password: hashPassword('root123')
    },
    {
        id: '685603b5-9ba8-4062-8ade-893ee77934e9',
        firstName: 'Felipe',
        lastName: 'cardenaz',
        email: 'felipe@gmail.com',
        password: hashPassword('root')
    },
    {
        id: '011b74d8-5881-4e53-a38d-cecfd38d1b32',
        firstName: 'Alan',
        lastName: 'Enciso',
        email: 'alan@gmail.com',
        password: hashPassword('1234')
    }
]

const createUsers = () => {
    Users.bulkCreate(userBases)
        .then(() => {
            console.log('User seeders executed')
            
        })
        .catch(console.log)
}

const deleteUsers = async() => {
    await Users.findAll()
            .then((data) => {
                data.map((user) => user.destroy({where:{id:user.id}}))
            })
            .catch(console.log)

}

module.exports = {
    createUsers,
    deleteUsers
}