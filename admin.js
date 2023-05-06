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
const axios = require('axios');

const mysql = require('./utils/mysql');
const qdrant = require('./utils/qdrant');
const jwtUtil = require('./utils/jwt');
const s3 = require('./utils/s3');
const routes = require('./routes');

const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require('uuid');

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const { JWT_SECRET, CONFIG_MYSQL_HOST, CONFIG_MYSQL_DATABASE, CONFIG_MYSQL_USER, CONFIG_MYSQL_PASSWORD } = process.env;

// app.use((req, res, next) => {
//     console.log(req);
//     next();
// })

const configPool = mysql.pool(CONFIG_MYSQL_HOST, CONFIG_MYSQL_DATABASE, CONFIG_MYSQL_USER, CONFIG_MYSQL_PASSWORD);




const userIdFromUserName = async userName => {
    const q = `SELECT user_id FROM account WHERE user_name = ${mysql.escape(userName)}`;

    let result;
    try {
        result = await mysql.query(configPool, q);
        if (result.length) return result[0].user_id;
        else return false;
    } catch (err) {
        console.error('userIdFromUserName', err);
        return false;
    }
}

const botBelongsToUserId = async (botId, userId) => {
    const q = `SELECT user_id, server_series FROM bots WHERE bot_id = '${botId}'`;

    let result;

    try {
        result = await mysql.query(configPool, q);
        if (!result.length) return false;
        if (result[0].user_id !== userId) return false;
        return result[0].server_series;
    } catch (err) {
        console.error('botBelongsToUserId', err);
        return false;
    }
}


const updateToken = async (userName, token) => {
    const q = `UPDATE account SET token = '${token}' WHERE user_name = '${userName}'`;
    return await mysql.query(configPool, q);
}

const setKey = (req, res) => {
    return new Promise(async (resolve, reject) => {
        const { token, key } = req.body;

        if (!token || !key) {
            res.status(400).json('bad request');
            return resolve('Error 001');
        } 

        tokenInfo = routes.extractToken(token);
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
        console.log('assignNewBot', req.body);
        const { token, botName, websites } = req.body;

        if (!token || !botName || !websites) {
            res.status(400).json('bad request');
            return resolve('error 400');
        }

        const decodedToken = routes.extractToken(token, true);

        if (!decodedToken.status) {
            res.status(401).json(decodedToken.msg);
            return resolve('error 401')
        }

        const tokenInfo = decodedToken.msg;
        console.log('tokenInfo', tokenInfo);

        const {userName, userId, openAIKeys} = tokenInfo;
        console.log('assignNewBot', userName, userId);

        let response;

        // assign bot uuid
        const botId = uuidv4();

        // get ingest, qdrant, and app servers
        /*
         * TODO: dynamically get names of these servers
         */

        const serverSeries = 1;
 
        // set bot info in bots table

        let domains = websites.replaceAll(',', "\n");
        domains = domains.split("\n");
        domains = domains.map(domain => domain.trim());
        console.log('domains', domains);

        const dbToken = jwt.sign({
            botId, openAIKey: openAIKeys[0], domains, serverSeries
        }, JWT_SECRET);

        let q = `INSERT INTO bots (user_id, bot_id, bot_name, websites, server_series, token) VALUES 
        ('${userId}', '${botId}', ${mysql.escape(botName)}, ${mysql.escape(websites)}, ${serverSeries}, '${dbToken}')`;

        try {
            await mysql.query(configPool, q);
        } catch (err) {
            res.status(500).json('Server Error: Could not insert bot info into database. Please try again later');
            return resolve('error 500');
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
            res.status(500).json('Server Error: Unable to generate qdrant collection for bot.');
            return resolve('error 500');
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
            res.status(500).json('Server Error: Could not setup bot js and css.');
            return resolve('error 500');
        }

        const botToken = jwt.sign({
            userName, serverSeries, botId, openAIKeys
        }, JWT_SECRET, {expiresIn: '1h'});

        res.status(200).json({botToken, serverSeries, botId});
        return resolve('ok')
    })
}

const listBots = (req, res) => {
    return new Promise(async (resolve, reject) => {
        const { token } = req.body;

        if (!token) {
            res.status(400).json('bad request');
            return resolve('error 400');
        }

        const tokenInfo = routes.extractToken(token);
        if (!tokenInfo.status) {
            res.status(401).json('unauthorized');
            return resolve('error 401');
        }

        const decodedToken = tokenInfo.msg;

        const { userName, userId } = decodedToken;

        let result;

        try {
            result = await mysql.query(configPool, `SELECT bot_id, bot_name, websites, server_series FROM bots WHERE user_id = '${userId}'`);
        } catch (err) {
            res.status(500).json('server error. unable to retrieve info regarding bots');
            return resolve('error 500');
        }

        const bots = result.map(bot => {
            return {
                botId: bot.bot_id, 
                botName: bot.bot_name, 
                websites: bot.websites,
                serverSeries: bot.server_series
            }
        })

        //console.log(bots);

        res.status(200).json(bots);
        resolve('ok');
    })
}

function error (num, msg, resolve, res) {
    res.status(num).json(msg);
    resolve(msg);
}

const deleteBotId = async (botId, serverSeries) => {
    const qdrantHost = `qdrant-${serverSeries}.instantchatbot.net`;
        const chunksHost = `chunks-${serverSeries}.instantchatbot.net`;

        let result = await qdrant.deleteCollection(qdrantHost, 6333, botId);
        console.log('qdrant result', result.data);
        
        const { CHUNKS_MYSQL_USER, CHUNKS_MYSQL_PASSWORD} = process.env;

        console.log('mysql credentials', CHUNKS_MYSQL_USER, CHUNKS_MYSQL_PASSWORD);

        const chunkDb = mysql.pool(chunksHost, 'chunks', CHUNKS_MYSQL_USER, CHUNKS_MYSQL_PASSWORD, 1);

        let q = `SELECT content_id FROM content WHERE bot_id = '${botId}'`;
        let contentIds = await mysql.query(chunkDb, q);
        console.log('contentIds', contentIds);
        
        for (let i = 0; i < contentIds.length; ++i) {
            let contentId = contentIds[i].content_id;
            q = `DELETE FROM chunk WHERE content_id = '${contentId}'`;
            result = await mysql.query(chunkDb, q);
            console.log(`Delete chunks for contentId ${contentId}: `, result);
        }

        q = `DELETE FROM content WHERE bot_id = '${botId}'`;
        result = await mysql.query(chunkDb, q);
        chunkDb.end();

        console.log(`Delete content for bot ${botId}`, result);

        const {S3_ENDPOINT, S3_ENDPOINT_DOMAIN, S3_REGION, S3_KEY, S3_SECRET, S3_BUCKET} = process.env;

        const s3Client = s3.client(S3_ENDPOINT, S3_ENDPOINT_DOMAIN, S3_REGION, S3_KEY, S3_SECRET, S3_BUCKET)

        result = await s3.emptyS3Directory(botId, s3Client);

        q = `DELETE FROM bots WHERE bot_id = '${botId}'`;
        await mysql.query(configPool, q);
        

}

const deleteBot = (req, res) => {
    return new Promise(async (resolve, request) => {
        const { botId, userToken } = req.body;

        if (!botId || !userToken) return error(400, 'bad request', resolve, res);

        const token = jwtUtil.getToken(userToken);

        console.log(token);

        const { userName } = token;

        const userId = await userIdFromUserName(userName);

        console.log('userId', userId);

        if (!userId) return error(401, 'unauthorized', resolve, res);

        const serverSeries = await botBelongsToUserId(botId, userId);

        console.log('server_series', serverSeries);

        if (serverSeries === false) return error(401, 'unauthorized 2', resolve, res);

        await deleteBotId(botId, serverSeries);

                /*
         * TODO: alter js and css on home?? 
         */
        
        res.status(200).json('ok');
        resolve('ok');
    })
}

const deleteAccount = (req, res) => {
    return new Promise(async(resolve, reject) => {
        const { userToken } = req.body;
    
        if (!userToken) return error(400, 'bad request', resolve, res);

        const token = jwtUtil.getToken(userToken);

        console.log(token);

        const { userName } = token;

        const userId = await userIdFromUserName(userName);

        console.log('userId', userId);

        if (!userId) return error(401, 'unauthorized', resolve, res);

        // get all botIds

        let q = `SELECT bot_id FROM bots WHERE user_id = '${userId}'`;
        let result = await mysql.query(configPool, q);

        console.log(result);

        for (let i = 0; i < result.length; ++i) {
            const botId = result[i].bot_id;
            const serverSeries = await botBelongsToUserId(botId, userId);

            console.log('server_series', serverSeries);

            if (serverSeries === false) continue;

            await deleteBotId(botId, serverSeries)
        }

        q = `DELETE FROM account WHERE user_id = '${userId}'`;
        result = await mysql.query(configPool, q);

        res.status(200).json('ok');
        resolve('ok');
    })
}

const purchaseCredits = async (req, res) => {
    url = '/home';

    let { userToken, quantity } = req.body;

    if (!userToken || !quantity) return res.status(400).json('bad request');

    if (isNaN(quantity)) return res.status(400).json('bad request 2');

    quantity = Math.trunc(Number(quantity));

    console.log ('quantity', quantity);

    const session = await stripe.checkout.sessions.create({
        payment_method_types: [
            'card'
        ],
        mode: 'payment', // 'subscription' would be for recurring charges,
        success_url: `https://instantchatbot.net/purchase?type=success&qty=${quantity}`,
        cancel_url: 'https://instantchatbot.net/purchase?type=cancel',
        line_items: [
            {
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: 'Instant Chatbot Credit',
                    },
                    unit_amount: 2000
                },
                quantity
            }
        ]
    })

    res.status(200).send(session.url);
   
    
}

app.use(express.static('public'));
app.use(express.json({limit: '200mb'})); 
app.use(cors());

app.get('/', (req, res) => {
    res.send('Hello, World!');
});

app.get('/verify', (req, res) => routes.verifyEmailToken(req, res));
app.post('/signup', (req, res) => routes.sendVerificationEmail(req, res));
app.post('/login', (req, res) => routes.handleLogin(req, res));
app.post('/key', (req, res) => setKey(req, res));
app.post('/newBot', (req, res) => assignNewBot(req, res));
app.post('/listBots', (req, res) => listBots(req, res));
app.post('/deleteBot', (req, res) => deleteBot(req, res));
app.post('/deleteAccount', (req, res) => deleteAccount(req, res));
app.post('/purchaseCredits', (req, res) => purchaseCredits (req,res));


const httpsServer = https.createServer({
    key: fs.readFileSync(privateKeyPath),
    cert: fs.readFileSync(fullchainPath),
  }, app);
  

  httpsServer.listen(listenPort, '0.0.0.0', () => {
    console.log(`HTTPS Server running on port ${listenPort}`);
});
