require('dotenv').config();
const axios = require('axios');

const { SMTP_COM_API_KEY, SMTP_COM_CHANNEL } = process.env;

console.log(SMTP_COM_API_KEY, SMTP_COM_CHANNEL);

exports.sendEmail = (recipientEmailAddress, senderEmailAddress, subject, html, fromName = '') => {
   return new Promise((resolve, reject) => {
       let request = {
           url: `https://api.smtp.com/v4/messages?api_key=${process.env.SMTP_COM_API_KEY}`,
           method: 'post',
           data: {
               "channel": process.env.SMTP_COM_CHANNEL,
               "recipients": {
                 "to": [
                   {
                     "address": recipientEmailAddress
                   }
                 ]
               },
               "originator": {
                 "from": {
                   "name": fromName ? fromName : senderEmailAddress,
                   "address": senderEmailAddress
                 }
               },
               "subject": subject,
               "body": {
                 "parts": [
                   {
                     "type": "text/html",
                     "content": html
                   }
                 ]
               }
             }
       }
    
       axios(request)
       .then(result => {
            console.log (result.data);
            resolve(result.data)       
           return;
       })
       .catch(err => {
           // TODO: add error function that not only sends errors to customers but logs them in the error database as well
           // TODO: use this error function for all res errors.
    
           console.log('error', JSON.stringify(err.data));
           reject(err)
           return;
       })
    
       return;
   })
}

const testEmail = () => {
    this.sendEmail('michaelwood33311@icloud.com', 'noreply@instantchatbot.net', 'Verify Email Address', "Hello, this is an email test", 'Instant ChatBot');
}

//testEmail();