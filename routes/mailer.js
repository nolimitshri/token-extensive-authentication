const mailer = require("nodemailer");
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Token = require("../models/tokens");

const transporter = mailer.createTransport({
    service: "gmail",
    port: 465,
    auth: {
        user: process.env.SENDER_EMAIL,
        pass: process.env.SENDER_PASSWORD
    }
});

module.exports.sendAnEmail = async(host, userEmail, userId) => {

    const uniqueToken = crypto.randomBytes(16).toString("hex");
    
    bcrypt.hash(uniqueToken, 10).then((hashedToken) => {
        
        const newToken = new Token({
          email: userEmail,
          userId: userId,
          uniqueToken: hashedToken,
          expiresAt: Date.now() + 21600000,
        });

        newToken.save().then(async(token) => {
            var url = `http://${host}/users/verify/${token.userId}/${uniqueToken}`;
            console.log(token + "\n" + url);

          await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: userEmail,
            subject: "Test Email by AVIPL",
            html: `
                <p>Verify your email address to complete the Registration process and Login to your Account.</p>
                <p>This link expires in 6 hours.</p>
                <p>Verify <a href=${url}>here</a>.</p>
            `
        }, (err, info) => {
            if(err){
                console.log(err);
            } else {
                console.log(info.response);
            }
        })
        }).catch(e => {
          console.log(e);
        })
      })
};