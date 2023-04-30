require('dotenv').config();
const listenPort = 6200;
const hostname = 'admin.instantchatbot.net'
const privateKeyPath = `/home/sslkeys/instantchatbot.net.key`;
const fullchainPath = `/home/sslkeys/instantchatbot.net.pem`;

const express = require('express');
const https = require('https');
const cors = require('cors');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const app = express();
const luxon = require('luxon');

const smtp = require('./utils/smtpCom');
const mysql = require('./utils/mysql');
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require('uuid');


const { JWT_SECRET, CONFIG_MYSQL_HOST, CONFIG_MYSQL_DATABASE, CONFIG_MYSQL_USER, CONFIG_MYSQL_PASSWORD } = process.env;

// app.use((req, res, next) => {
//     console.log(req);
//     next();
// })

const configPool = mysql.pool(CONFIG_MYSQL_HOST, CONFIG_MYSQL_DATABASE, CONFIG_MYSQL_USER, CONFIG_MYSQL_PASSWORD);

const getPasswordHash = (password, saltRounds = 10) => bcrypt.hash(password, saltRounds);

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

function extractToken(info, expiredCheck = false) {
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

const sendVerificationEmail = (req, res) => {
    return new Promise(async (resolve, reject) => {
  
    const { email, userName, password } = req.body;

    if (!email || !userName || !password) {
        res.status(400).json('bad request');
        return resolve('error 001');
    } 

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
        res.status(400).json('Unable to send verification email');
        return resolve('error 002');
    }

    res.status(200).json('ok');

    resolve('ok');

    return;

    })
}

const verifyEmailToken = (req, res) => {
    return new Promise(async (resolve, reject) => {
        if (!req.query || !req.query.t) {
            res.status(400).json('bad request');
            return resolve('error 001');
        }
        const token = extractToken(req.query.t);
    
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
            userName, userId, storageTokens: 1000000, queryTokens: 20, openAIKeys: []
        }, JWT_SECRET, {expiresIn: '12h'});

        const q = `INSERT INTO account (user_id, user_name, email, password, allowed_storage_tokens, allowed_query_tokens, storage_tokens, query_tokens, reset_date, expiration, token, status) VALUES
        ('${userId}', '${userName}', '${email}', '${passwordHash}', ${1000000}, ${20}, ${1000000}, ${20}, '${oneMonth}', '${oneMonth}', '${newToken}', '${JSON.stringify({status: 'verified'})}')`

        let result = await mysql.query(configPool, q);

        res.redirect('https://instantchatbot.net/login')
        return resolve('ok');
    })
}

const updateToken = async (userName, token) => {
    const q = `UPDATE account SET token = '${token}' WHERE user_name = '${userName}'`;
    return await mysql.query(configPool, q);
}

const getUserInfo = async (userName, password = '') => {
    const q = `SELECT user_id, password, storage_tokens, query_tokens, token FROM account WHERE user_name = ${mysql.escape(userName)}`;
    return await mysql.query(configPool, q);
}

const sendUserInfo = (userName, res, password) => {
    return new Promise (async (resolve, reject) => {

        const result = await getUserInfo(userName);

        if (!result.length) {
            res.status(401).json('unauthorized');
            return resolve('error 401');
        }

        const hash = result[0].password;
    
        const test = await isValidUser(password, hash);
    
        if (!test) {     
            res.status(401).json('unauthorized');
            return resolve('error 402');
        }
        
    
        const storageTokens = result[0].storage_tokens;
        const queryTokens = result[0].query_tokens;
        const token = result[0].token;
        const userId = result[0].user_id;

        const tokenInfo = extractToken(token);

        console.log('extracting token', token);

        if (!tokenInfo.status) {
            res.status(500).json('cannot decode token');
            return resolve('error 500');
        }

        console.log('token info', tokenInfo);

        const hasKey = tokenInfo.msg.openAIKeys.length ? true : false;

        const newToken = jwt.sign({
            userName, userId, storageTokens, queryTokens, openAIKeys: tokenInfo.msg.openAIKeys
        }, JWT_SECRET, {expiresIn: '12h'});
        
        res.status(200).json({userId, userName, storageTokens, queryTokens, hasKey, token: newToken});

        resolve ('ok');
        return
    })
}

const handleLogin = (req, res) => {
    return new Promise(async (resolve, reject) => {
        const { userName, password } = req.body;

        if (!userName || !password) {
            res.status(400).json('bad request');
            resolve('error 001');
            return;
        }

        sendUserInfo(userName, res, password);
       
    })
}

const setKey = (req, res) => {
    return new Promise(async (resolve, reject) => {
        const { token, key } = req.body;

        if (!token || !key) {
            res.status(400).json('bad request');
            return resolve('Error 001');
        } 

        tokenInfo = extractToken(token);
        const { userName } = tokenInfo.msg;

        console.log('token', userName, tokenInfo, key);

        const result = await getUserInfo(userName);

        const storageTokens = result[0].storage_tokens;
        const queryTokens = result[0].query_tokens;    
        const hasKey = true;

        const newToken = jwt.sign({
            userName, storageTokens, queryTokens, openAIKeys: [key]
        }, JWT_SECRET, {expiresIn: '12h'});

        await updateToken(userName, newToken);

        res.status(200).json({userName, storageTokens, queryTokens, hasKey, token: newToken});

        return resolve('ok');
    })
}

const assignNewBot = (req, res) => {
    return new Promise (async (resolve, reject) => {

        const { token, botName, websites, openAIKeys } = req.body;

        if (!token || !botName || !websites || !openAIKeys || !openAIKeys.length) {
            res.status(400).json('bad request');
            return resolve('error 400');
        }

        const decodedToken = extractToken(token, true);

        if (!decodedToken.status) {
            res.status(401).json(decodedToken.msg);
            return resolve('error 401')
        }

        const tokenInfo = decodedToken.msg;

        const {userName, userId} = tokenInfo;
        console.log('assignNewBot', userName, userId);

        // assign bot uuid
        const botId = uuidv4();

        // get ingest, qdrant, and app servers
        /*
         * TODO: dynamically get names of these servers
         */

        const serverSeries = 1;

        // set bot info in bots table

        let q = `INSERT INTO bots (user_id, bot_id, bot_name, websites, server_series) VALUES 
        ('${userId}', '${botId}', ${mysql.escape(botName)}, ${mysql.escape(websites)}, ${serverSeries})`;

        try {
            await mysql.query(configPool, q);
        } catch (err) {
            res.status(500).json('Server Error: Could not insert bot info into database. Please try again later');
            return resolve('error 500');
        }


        const botToken = jwt.sign({
            userName, serverSeries, botId, openAIKeys
        }, JWT_SECRET, {expiresIn: '1h'});

        res.status(200).json({botToken, serverSeries, botId});
        return resolve('ok')
    })
}

app.use(express.static('public'));
app.use(express.json({limit: '200mb'})); 
app.use(cors());

app.get('/', (req, res) => {
    res.send('Hello, World!');
});

app.get('/verify', (req, res) => verifyEmailToken(req, res));
app.post('/signup', (req, res) => sendVerificationEmail(req, res));
app.post('/login', (req, res) => handleLogin(req, res));
app.post('/key', (req, res) => setKey(req, res));
app.post('/newBot', (req, res) => assignNewBot(req, res));

const httpsServer = https.createServer({
    key: fs.readFileSync(privateKeyPath),
    cert: fs.readFileSync(fullchainPath),
  }, app);
  

  httpsServer.listen(listenPort, '0.0.0.0', () => {
    console.log(`HTTPS Server running on port ${listenPort}`);
});
