const express = require('express');
const router = express.Router();
const db = require('./../db');
const bcrypt = require('bcrypt');
const requireAuth = require('../middleware/authMiddleware');


//Sign Up
router.post('/users', async (req, res) => {

    try {
       const user = getUser(req.body);
        const hashedPassword = await bcrypt.hash(user.password, 10);

        await db.query(`INSERT INTO users (first_name, last_name, email_id, password) VALUES (?, ?, ?, ?)`, [user.firstName, user.lastName, user.email, hashedPassword]);
        res.redirect(`/login.html?message=${encodeURIComponent(`Username ${user.email} created successfully`)}`);
        // res.status(201).json({message: `Username ${name} created successfully`});
    } catch(err) {
        console.error(err);
        res.status(500).json({error : err.message});
    }
    
});

//Sign In
router.post('/users/login', requireAuth, async (req, res) => {
    try {
        const email = req.body.email;
        const password = req.body.password;

        const [ user1 ] = await db.query(`SELECT id, email_id, password FROM users WHERE email_id = ?`, [email] );
        const user = user1[0];
        if(user == null || user == undefined) {
            res.status(401).json('Username/Password is incorrect. Please try again');
        } else {
            if(await bcrypt.compare(password, user.password)) {
                req.session.userId = user.id;
                res.redirect('/home.html');
            } else {
                res.status(401).json('Username/Password is incorrect. Please try again');
            }
        }
    } catch (err) {
        console.error(err.message);
        res.status(500).json( {error : err.message} );
    }
});

router.post('/users/logout', (req, res) => {
    req.session.destroy((err) => {
        if(err) {
            return res.status(500).json({ error: "Sign Out Failed"});
        }

        res.sendStatus(200);
    });
});

function getUser(reqBody) {
    const user = {
        firstName: reqBody.firstName,
        lastName: reqBody.lastName,
        email: reqBody.email,
        password: reqBody.password 
    }

    return user;
}


module.exports = router;