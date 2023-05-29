const express = require('express');
const router = express.Router();
const userService = require('./user.service');
const jwt = require('jsonwebtoken')
const config = require('../config.js')

// routes
router.post('/authenticate', authenticate);
router.get('/logout', logout);
router.post('/register', register);
router.get('/audit',validateAuthAuditor, audit);
router.get('/', validateAuthUser, getAll);
router.get('/current', getCurrent);
router.get('/:id', getById);
router.put('/:id', update);
router.delete('/:id', _delete);

module.exports = router;


function audit (req, res, next) {
    userService.audit()
        .then(user => user ? res.json(user) : res.status(400).json({ message: 'Username or password is incorrect' }))
        .catch(err => next(err));
}

function authenticate(req, res, next) {

    userService.authenticate(req.body, req.socket.remoteAddress)
        .then(user => user ? res.json(user) : res.status(400).json({ message: 'Username or password is incorrect' }))
        .catch(err => next(err));
}

function logout(req, res, next) {
    const token = req.headers.authorization
    const decode = jwt.decode(token, config.secret)
    console.log(decode)
    userService.logout (decode.sub).then(user => user ? res.json(user) : res.status(400).json({ message: 'Username or password is incorrect' }))
    .catch(err => next(err));
}

function validateAuthUser(req, res, next) {
    const token = req.headers.authorization
    const decode = jwt.decode(token, config.secret)
    if(decode){
        console.log(decode)
        res.userId = decode.sub
        userService.getById(res.userId)
        .then((user)=>{
            console.log(user)
            if(user.role == "USER")
            next()
            else
            res.status(401).send("Unauthorized")
        })
        .catch(err => next(err));
    }else{
        res.status('401').send("Unauthorized")
    }
}
function validateAuthAuditor(req, res, next) {
    const token = req.headers.authorization
    const decode = jwt.decode(token, config.secret)
    res.userId = decode.sub
    if(decode){
        userService.getById(res.userId)
        .then((user)=>{
            if(user.role == "AUDITOR")
            next()
            else
            res.status(401).send("Unauthorized")
        })
        .catch(err => next(err));
    }else{
        res.status('401').send("Unauthorized")
    }
}

function register(req, res, next) {
    req.body.role = req.body.role ? req.body.role.toUpperCase() : ""
    if (req.body.role == 'USER' || req.body.role == 'AUDITOR') {
        userService.create(req.body)
            .then(() => res.json({}))
            .catch(err => next(err));
    } else {
        const err = new Error('Please provide a right user role')
        next(err)
    }

}

function getAll(req, res, next) {
    userService.getAll()
        .then(users => res.json(users))
        .catch(err => next(err));
}

function getCurrent(req, res, next) {
    userService.getById(req.user.sub)
        .then(user => user ? res.json(user) : res.sendStatus(404))
        .catch(err => next(err));
}

function getById(req, res, next) {
    userService.getById(req.params.id)
        .then(user => user ? res.json(user) : res.sendStatus(404))
        .catch(err => next(err));
}

function update(req, res, next) {
    userService.update(req.params.id, req.body)
        .then(() => res.json({}))
        .catch(err => next(err));
}

function _delete(req, res, next) {
    userService.delete(req.params.id)
        .then(() => res.json({}))
        .catch(err => next(err));
}