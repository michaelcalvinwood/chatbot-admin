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
const pendingPurchases = {};

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

    console.log('req.body', req.body);

    let { userToken, quantity, cost, discount} = req.body;

    if (!userToken || !quantity || !cost || typeof discount === 'undefined') return res.status(400).json('bad request');

    const token = jwtUtil.getToken(userToken);

    console.log('token', token);

    const { userId, userName, email } = token;

    if (isNaN(quantity)) return res.status(400).json('bad request 2');
    if (isNaN(cost)) return res.status(400).json('bad request 3');

    if (pendingPurchases[userId]) return res.status(400).json('bad request: already pending purchase');
    else pendingPurchases[userId] = res;

    quantity = Math.trunc(Number(quantity));

    console.log ('quantity', quantity);

    const session = await stripe.checkout.sessions.create({
        payment_method_types: [
            'card'
        ],
        mode: 'payment', // 'subscription' would be for recurring charges,
        success_url: `https://admin.instantchatbot.net:6200/successfulPurchase?qty=${quantity}&userId=${userId}`,
        cancel_url: `https://admin.instantchatbot.net:6200/failedPurchase?userId=${userId}`,
        line_items: [
            {
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: `Instant Chatbot Credit: ${quantity} Tokens`,
                    },
                    unit_amount: cost
                },
                quantity: 1
            }
        ]
    })

    res.status(200).send(session.url);
   
    
}

const handleSuccessfulPurchase = async (req, res) => {
    console.log('handleSuccessfulPurchase', req.query, pendingPurchases);

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
app.post('/setKey', (req, res) => routes.setKey(req, res));
app.post('/newBot', (req, res) => routes.assignNewBot(req, res));
app.post('/listBots', (req, res) => listBots(req, res));
app.post('/deleteBot', (req, res) => deleteBot(req, res));
app.post('/deleteAccount', (req, res) => deleteAccount(req, res));
app.post('/purchaseCredits', (req, res) => purchaseCredits (req,res));

app.get('/successfulPurchase', (req, res) => handleSuccessfulPurchase(req, res));
app.get('/failedPurchase', (req, res) => handleFailedPurchase(req, res));

const httpsServer = https.createServer({
    key: fs.readFileSync(privateKeyPath),
    cert: fs.readFileSync(fullchainPath),
  }, app);
  

  httpsServer.listen(listenPort, '0.0.0.0', () => {
    console.log(`HTTPS Server running on port ${listenPort}`);
});
