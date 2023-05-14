require('dotenv').config();
const { SERVER_SERIES } = process.env;
const serverSeries = Number(SERVER_SERIES);


const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require("bcrypt");
const luxon = require('luxon');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

const smtp = require('./utils/smtpCom');
const mysql = require('./utils/mysql');
const qdrant = require('./utils/qdrant');

const { JWT_SECRET, CONFIG_MYSQL_HOST, CONFIG_MYSQL_DATABASE, CONFIG_MYSQL_USER, CONFIG_MYSQL_PASSWORD } = process.env;

const configPool = mysql.pool(CONFIG_MYSQL_HOST, CONFIG_MYSQL_DATABASE, CONFIG_MYSQL_USER, CONFIG_MYSQL_PASSWORD);

const chunksHost = `chunks-${SERVER_SERIES}.instantchatbot.net`;
const qdrantHost = `qdrant-${SERVER_SERIES}.instantchatbot.net`;
const appHost = `app-${SERVER_SERIES}.instantchatbot.net`;

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

exports.verifyEmailToken = async (req, res) => {
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

        const q = `INSERT INTO account (user_id, user_name, email, password, next_charge_date, credit, token, status) VALUES
        ('${userId}', '${userName}', '${email}', '${passwordHash}', '${oneMonth}', 500, '${newToken}', '${JSON.stringify({status: 'verified'})}')`

        let result = await mysql.query(configPool, q);

        res.redirect('https://instantchatbot.net/login')
        return resolve('ok');
    })
}
const isValidUser = async (password, hash) => 
{
    let res;
    try {
       res = await bcrypt.compare(password, hash);
    } catch (err) {
        return false;
    }
    
    return res;
}

const getUserInfo = async (userName, password = '') => {
    const q = `SELECT user_id, email, password, token FROM account WHERE user_name = ${mysql.escape(userName)}`;
    return await mysql.query(configPool, q);
}

const sendUserInfo = async (userName, res, password) => {
        const result = await getUserInfo(userName);

        if (!result.length) return res.status(401).json('unauthorized');

        const hash = result[0].password;
    
        const test = await isValidUser(password, hash);
    
        if (!test) return res.status(401).json('unauthorized');
            
        const token = result[0].token;
        const userId = result[0].user_id;
        const email = result[0].email;

        const tokenInfo = exports.extractToken(token);

        console.log('extracting token', token);

        if (!tokenInfo.status) return res.status(500).json('cannot decode token');
           
        console.log('token info', tokenInfo);

        const hasKey = tokenInfo.msg.openAIKeys.length ? true : false;

        const newToken = jwt.sign({
            userName, userId, email, openAIKeys: tokenInfo.msg.openAIKeys
        }, JWT_SECRET, {expiresIn: '12h'});
        
        res.status(200).json({userId, userName, hasKey, token: newToken});
        return
}

exports.handleLogin = async (req, res) => {
        const { userName, password } = req.body;
        if (!userName || !password) return res.status(400).json('bad request');
            
        sendUserInfo(userName, res, password);
    
}

const updateToken = async (userName, token) => {
    const q = `UPDATE account SET token = '${token}' WHERE user_name = '${userName}'`;
    return await mysql.query(configPool, q);
}

exports.setKey = async (req, res) => {
        const { token, key } = req.body;

        if (!token || !key) return res.status(400).json('bad request');
            
        tokenInfo = exports.extractToken(token);
        const { userName } = tokenInfo.msg;

        console.log('token', userName, tokenInfo, key);

        const result = await getUserInfo(userName);
        const userId = result[0].user_id;
        const email = result[0].email;

        const hasKey = true;

        const newToken = jwt.sign({
            userId, userName, email, openAIKeys: [key]
        }, JWT_SECRET, {expiresIn: '12h'});

        await updateToken(userName, newToken);

        return res.status(200).json({userId, userName, email, hasKey, token: newToken});
}

exports.assignNewBot = async (req, res) => {
        console.log('assignNewBot', req.body);
        const { token, botName, websites, botType } = req.body;

        if (!token || !botName || typeof websites === 'undefined') return res.status(400).json('bad request');
     
        const decodedToken = exports.extractToken(token, true);

        if (!decodedToken.status) return res.status(401).json(decodedToken.msg);

        const tokenInfo = decodedToken.msg;
        console.log('tokenInfo', tokenInfo);

        const {userName, userId, openAIKeys} = tokenInfo;
        console.log('assignNewBot', userName, userId);

        let response;

        // assign bot uuid
        const botId = uuidv4();

        /*
         * TODO: dynamically get names of these servers
         */

        const serverSeries = 1;
 
        // set bot info in bots table

        let domains = websites ? websites.replaceAll(',', "\n") : '';
        domains = domains.split("\n");
        domains = domains.map(domain => domain.trim());
        console.log('domains', domains);

        const dbToken = jwt.sign({
            botId, userId, openAIKey: openAIKeys[0], domains, serverSeries, botType
        }, JWT_SECRET);

        let q = `INSERT INTO bots (user_id, bot_id, bot_name, websites, server_series, token, bot_type) VALUES 
        ('${userId}', '${botId}', ${mysql.escape(botName)}, ${mysql.escape(websites)}, ${serverSeries}, '${dbToken}','${botType}')`;

        try {
            await mysql.query(configPool, q);
        } catch (err) {
            return res.status(500).json('Server Error: Could not insert bot info into database. Please try again later');
        }

        // Create qdrant collection for the bot

        const qdrantHost = `qdrant-${serverSeries}.instantchatbot.net`;
        try {
            await qdrant.createOpenAICollection(botId, qdrantHost, 6333, true);
        } catch (err) {
            if (err.response && err.response.data) console.log(err.response.data)
            else console.error(err);
            q = `DELETE FROM bots WHERE bot_id = '${botId}'`;
            try {
                await mysql.query(configPool, q);
            } catch (err) {

            }
            return res.status(500).json('Server Error: Unable to generate qdrant collection for bot.');
            
        }

        // generate the js and css on the home server

        request = {
            url: 'https://instantchatbot.net:6202/addBot',
            method: 'post',
            data: {
                secretKey: process.env.SECRET_KEY,
                botToken: dbToken,
                serverSeries,
                botId
            }
        }

        console.log(request);

        try {
            response = await axios(request);
        } catch(err) {
            console.error(err);
            return res.status(500).json('Server Error: Could not setup bot js and css.');
        }

        const botToken = jwt.sign({
            userId, userName, serverSeries, botId, domains, openAIKeys, botType
        }, JWT_SECRET, {expiresIn: '1h'});

        return res.status(200).json({botToken, serverSeries, botId});
       
}
