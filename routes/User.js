const router = require('express').Router();
const e = require('express');
const mongodb = require('mongodb');
const { hashing, compareHash, generateToken, sendUserMail, verifyJwtToken } = require('../modules');
const mongoClient = mongodb.MongoClient;
const dburi = process.env.ATLAS_URI;

//get all users
router.route('/').get(async (req, res) => {
    let client = await mongoClient.connect(dburi);
    try {
        let db = client.db('gdrive-users');
        const data = await db.collection('users').find().toArray();
        res.json(data);
    } catch (error) {
        res.status(400).json('Error: ' + error)
    } finally {
        client.close();
    }
})

//Register a user
router.route('/register').post(async (req, res) => {
    let client = await mongoClient.connect(dburi);

    try {
        let db = client.db('gdrive-users');
        const existingData = await db.collection('users').find({ email: req.body.email }).toArray();
        if (!existingData.length) {
            let emailToken = generateToken({ email: req.body.email });
            let newUser = {
                ...req.body, active: false, password: await hashing(req.body.password), token: emailToken
            }
            const data = await db.collection('users').insertOne(newUser);
            if (data) {
                sendUserMail('verifyUser', emailToken, 'Verify User Registration', 'Please click on the Link to complete your registration', req.body.email);
                res.status(201).json({ message: "Register Success. Please Check your email" })
            } else {
                res.status(400).json('Error: Could not register User.Please try again!!!');
            }
        } else {
            res.status(400).json({ message: 'User with this Email/Username already exists' });
        }



    } catch (error) {
        console.log(error)
        res.status(400).json('Error: ' + error)
    } finally {
        client.close();
    }
})

//login a user
router.route('/login').post(async (req, res) => {
    let client = await mongoClient.connect(dburi);

    try {
        let db = client.db('gdrive-users');
        const data = await db.collection('users').find({ username: `${req.body.email}` }).toArray();
        if (data) {
            let userLogin = compareHash(req.body.password, data[0].password);
            if (userLogin) {
                res.status(200).json({ token: generateToken({ email: data[0].email }), firstName: data[0].firstName, lastName: data[0].secondName })
            } else {
                res.status(400).json({ message: "Username or Password incorrect" })
            }
        }

    } catch (error) {
        res.status(400).json('Error: ' + error)
    } finally {
        client.close();
    }
})


//Verify user in browser
router.route('/verifyUser/:token').get(async (req, res) => {

    let client = await mongoClient.connect(dburi);
    try {
        let userToken = req.params.token;
        if (verifyJwtToken(userToken)) {
            let db = client.db('gdrive-users');
            const verifyDBToken = await db.collection('users').find({ username: `${verifyJwtToken(userToken).email}` }).toArray();
            if (!verifyDBToken[0]['active'] && verifyDBToken[0].token) {
                const data = await db.collection('users').updateOne({ _id: verifyDBToken[0]._id }, { $set: { active: true, token: '' } });
                res.status(200).json({ message: "User verified and Logged in", token: userToken })
            } else {
                res.status(400).json({ message: 'Error: Token Expired/invalid' })
            }
        } else {
            res.json({ message: 'invalid token' })
        }

    } catch (error) {
        res.status(400).json('Error: ' + error)
    } finally {
        client.close();
    }
})

//Verify user
router.route('/verifyUser/:token').get(async (req, res) => {

    let client = await mongoClient.connect(dburi);
    try {
        let userToken = req.params.token;
        if (verifyJwtToken(userToken)) {
            let db = client.db('gdrive-users');
            const verifyDBToken = await db.collection('users').find({ username: `${verifyJwtToken(userToken).email}` }).toArray();
            if (!verifyDBToken[0]['active'] && verifyDBToken[0].token) {
                const data = await db.collection('users').updateOne({ _id: verifyDBToken[0]._id }, { $set: { active: true } });
                res.status(200).json({ message: "User verified and Logged in", token: userToken })
            } else {
                res.status(400).json('Error: Token Expired/invalid')
            }
        } else {
            res.json({ message: 'invalid token' })
        }

    } catch (error) {
        res.status(400).json('Error: ' + error)
    } finally {
        client.close();
    }
})


//check if user exists
router.route('/resetPassword/checkUser').post(async (req, res) => {
    let client = await mongoClient.connect(dburi);

    try {
        let db = client.db('gdrive-users');
        const data = await db.collection('users').find({ username: req.body.email }).toArray();
        if (data.length) {
            let emailToken = generateToken({ email: req.body.email })
            let updateTokenToUser = await db.collection('users').updateOne({ _id: data[0]._id }, { $set: { active: false, token: emailToken } });
            if (updateTokenToUser) {
                sendUserMail('resetPassword', emailToken, 'Reset Password', 'Please click on the Link to complete reseting your password', req.body.email);
                res.status(201).json({ message: "Please Check your email for resetting your password" })
            } else {
                res.status(400).json({ message: 'Username/email invalid' })
            }


        } else {
            res.status(400).json({ message: "Username or Password incorrect" })
        }
    } catch (error) {
        res.status(400).json('Error: ' + error)
    } finally {
        client.close();
    }
})


//check if user exists
router.route('/resetPassword/newPassword').post(async (req, res) => {
    let client = await mongoClient.connect(dburi);
    try {
        let db = client.db('gdrive-users');
        let email = verifyJwtToken(req.body.token).email
        const data = await db.collection('users').find({ username: email }).toArray();
        if (data.length && data[0].token) {
            let updatePassword = await db.collection('users').updateOne({ _id: data[0]._id }, { $set: { password: await hashing(req.body.password), token: '' } });
            if (updatePassword) {

                res.status(201).json({ message: "Password Reset Success. Please login with Email and New Password" })
            } else {
                res.status(400).json({ message: 'Password reset failed. Please try again' })
            }


        } else {
            res.status(400).json({ message: "Token Expreired/Invalid" })
        }
    } catch (error) {
        res.status(400).json('Error: ' + error)
    } finally {
        client.close();
    }
})


module.exports = router;