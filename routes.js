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
