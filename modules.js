const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

var nodemailer = require('nodemailer');


const hashing = async (value) => {
    try {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(value, salt);
        return hash;
    } catch (err) {
        return err;
    }
}

const compareHash = (value, hash) => {
    try {

        return bcrypt.compareSync(value, hash);
    } catch (err) {
        return err;
    }

}

const generateToken = (object) => {
    return jwt.sign(object, process.env.ACCESS_TOKEN_SECRET)
}

verifyJwtToken = (token) => {
    return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

}

generateTokenLink = (route, token) => {
    // `http://localhost:8080/user/${route}/${token}`;
    return `http://localhost:3000/verifyUser/${route}/${token}`;
}




const sendUserMail = (route, token, subject, message, email) => {
    var transporter = nodemailer.createTransport({
        service: 'gmail',
        host: 'smtp.gmail.com',
        auth: {
            user: process.env.NODEMAILER_USERNAME,
            pass: process.env.NODEMAILER_PASSWORD
        }
    });
    var mailOptions = {
        from: 'drive-clone@guvi-hackathon.com',
        to: email,
        subject: subject,
        text: `${message} ${generateTokenLink(route, token)}`
    };

    transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
            console.log(error);
            return true;
        } else {
            console.log('Email sent: ' + info.response);
            return false

        }
    });
}

module.exports = { hashing, compareHash, generateToken, sendUserMail, verifyJwtToken }

