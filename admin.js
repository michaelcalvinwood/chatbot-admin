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

const { JWT_SECRET } = process.env;

// app.use((req, res, next) => {
//     console.log(req);
//     next();
// })

function extractToken(info) {
    // if invalid return false
    try {
        if (!jwt.verify(info, process.env.SECRET_KEY)) return {status: false, msg: 'invalid token'};
    } catch (err) {
        return {status: false, msg: 'invalid token'}
    }
    const token = jwt.decode(info);
    const curTime = new Date();

    // if expired return false
    if (token.exp < curTime.getTime()/1000) return {status: false, msg: 'token has expired'};

    return {status: true, msg: token};
}

app.use(express.static('public'));
app.use(express.json({limit: '200mb'})); 
app.use(cors());

app.get('/', (req, res) => {
    res.send('Hello, World!');
});

app.get('/verify', (req, res) => {
    if (!req.query || !req.query.t) return res.status(400).json('bad request');

    const token = extractToken(req.query.t);

    if (!token.status) return res.status(400).json(token.msg);

    console.log(token.msg);

    res.status(200).json('ok');
})

app.post('/signup', (req, res) => {
    const { email, userName, password } = req.body;

    if (!email || !userName || !password) return res.status(400).json('bad request');

    console.log(userName, email, password);

    /*
     * TODO: Add server-side validation of email, password, and username
     */

    res.status(200).json('ok');

})

const httpsServer = https.createServer({
    key: fs.readFileSync(privateKeyPath),
    cert: fs.readFileSync(fullchainPath),
  }, app);
  

  httpsServer.listen(listenPort, '0.0.0.0', () => {
    console.log(`HTTPS Server running on port ${listenPort}`);
});
