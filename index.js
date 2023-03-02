require('dotenv').config({path: '.env'})
const express = require('express')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const passport = require('passport')
const {Strategy: LocalStrategy, ExtractJwt} = require('passport-jwt')

const privateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY)
const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY)

// console.log(privateKey.toString())

const app = express()
const port = process.env.PORT

const passportLib = passport.use(new LocalStrategy({
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: process.env.JWT_KEY
}, (payload, done) => {
    const {user_id} = payload

    done(null, {user_id})
}))

app.use(passportLib.initialize());
app.use(express.json())

app.post('/v1/register/asynchronous', (req, res, next) => {
    const {
        user_id,
        role
    } = req.body

    const payload = {
        user_id,
        role
    }

    const token = jwt.sign(payload, privateKey, {expiresIn: '1h', algorithm: 'RS256'})

    return res.status(200).json({token})
})

app.post('/v1/validate/asynchronous', (req, res, next) => {
    const {token} = req.body

    const decoded = jwt.verify(token, publicKey, {algorithms: 'RS256'})

    return res.status(200).json(decoded)
})

app.post('/v1/register/basic', (req, res, next) => {
    const {
        user_id,
        role
    } = req.body

    const payload = {
        user_id,
        role
    }

    const token = jwt.sign(payload, process.env.JWT_KEY, {expiresIn: '1h', algorithm: 'HS256'})

    return res.status(200).json({token})
})

app.post('/v1/validate/basic/passport', passportLib.authenticate('jwt', {session: false}), (req, res, next) => {
    return res.status(200).json(req.user)
})

app.get('/home', (req, res, next) => {
    return res.status(200).json({message: 'Tada! anda salah'})
})

app.post('/v1/validate/basic', (req, res, next) => {
    const {token} = req.body

    const decoded = jwt.verify(token, process.env.JWT_KEY, {algorithms: 'HS256'})

    return res.status(200).json(decoded)
})

app.listen(port, () => {
    console.log(`server up on port: ${port}`)
}) 