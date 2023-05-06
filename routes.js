require('dotenv').config();
const fs = require('fs');
const jwt = require('jsonwebtoken');
const smtp = require('./utils/smtpCom');
const bcrypt = require("bcrypt");
const mysql = require('./utils/mysql');
const { v4: uuidv4 } = require('uuid');
const luxon = require('luxon');

const { JWT_SECRET, CONFIG_MYSQL_HOST, CONFIG_MYSQL_DATABASE, CONFIG_MYSQL_USER, CONFIG_MYSQL_PASSWORD } = process.env;

const configPool = mysql.pool(CONFIG_MYSQL_HOST, CONFIG_MYSQL_DATABASE, CONFIG_MYSQL_USER, CONFIG_MYSQL_PASSWORD);

const getPasswordHash = (password, saltRounds = 10) => bcrypt.hash(password, saltRounds);

exports.sendVerificationEmail = async (req, res) => {
    const { email, userName, password } = req.body;

    if (!email || !userName || !password) return res.status(400).json('bad request');
    console.log(userName, email, password);

    /*
     * TODO: Add server-side validation of email, password, and username
     */


    let emailTemplate = fs.readFileSync('./email.html', 'utf-8');
    let token = jwt.sign({
        email, userName, password
    }, JWT_SECRET, {expiresIn: '3h'});

    let verificationEmail = emailTemplate.replaceAll('TOKEN_URL', `https://admin.instantchatbot.net:6200/verify?t=${token}`);

    let result;
    
    try {
        result = await smtp.sendEmail(email, 'noreply@instantchatbot.net', 'Verify Email Address', verificationEmail, "Instant Chatbot");
    } catch (err) {
        console.error('Error [sendVerificationEmail]', err.message ? err.message : err)
        return res.status(400).json('Unable to send verification email');
    }

    return res.status(200).json('ok');
}

exports.extractToken = (info, expiredCheck = false) => {
    // if invalid return false
    try {
        if (!jwt.verify(info, JWT_SECRET)) return {status: false, msg: 'invalid token'};
    } catch (err) {
        if (err.name && err.name === 'TokenExpiredError' && expiredCheck === false) return ({status:true, msg: jwt.decode(info)}) 
        console.error(JSON.stringify(err));
        return {status: false, msg: 'invalid token'}
    }
    const token = jwt.decode(info);

    if (expiredCheck) {
        const curTime = new Date();
        if (token.exp < curTime.getTime()/1000) return {status: false, msg: 'token has expired'};
    }

    return {status: true, msg: token};
}

exports.verifyEmailToken = (req, res) => {
    return new Promise(async (resolve, reject) => {
        if (!req.query || !req.query.t) {
            res.status(400).json('bad request');
            return resolve('error 001');
        }
        const token = exports.extractToken(req.query.t);
    
        if (!token.status) {
            res.status(400).json(token.msg);
            return resolve ('error 002');
        } 
    
        const info = token.msg;

        const { email, userName, password } = info;

        console.log(info);

        const passwordHash = await getPasswordHash(password);
        const userId = uuidv4();
        const oneMonth = luxon.DateTime.now().plus({months: 1}).toISODate();
        const newToken = jwt.sign({
            userName, userId, email, openAIKeys: []
        }, JWT_SECRET, {expiresIn: '12h'});

        const q = `INSERT INTO account (user_id, user_name, email, password, next_charge_date, remaining_credit, token, status) VALUES
        ('${userId}', '${userName}', '${email}', '${passwordHash}', '${oneMonth}', 500, '${newToken}', '${JSON.stringify({status: 'verified'})}')`

        let result = await mysql.query(configPool, q);

        res.redirect('https://instantchatbot.net/login')
        return resolve('ok');
    })
}
