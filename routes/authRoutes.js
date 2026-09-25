const express = require('express');
const router = express.Router();
const db = require('./../db');
const bcrypt = require('bcrypt');
const requireAuth = require('../middleware/authMiddleware');


//Sign Up
router.post('/users', async (req, res) => {

    try {
        const user = getUser(req.body);
        const validationError = validateUserInput(user);

        if (validationError) {
            return res.status(400).json({
                error: 'Sign Up Failed',
                message: validationError
            });
            
        }

        const [rows] = await db.query(`SELECT email_id FROM users WHERE email_id = (?)`, [user.email]);
        if(rows.length > 0) {
            return res.status(409).json({error: 'Sign Up Failed', 
                message: 'User with given email address already exists'});
        }
        
        const hashedPassword = await bcrypt.hash(user.password, 10);
        await db.query(`INSERT INTO users (first_name, last_name, email_id, password) VALUES (?, ?, ?, ?)`, [user.firstName, user.lastName, user.email, hashedPassword]);
        res.redirect(`/login.html?message=${encodeURIComponent(`Username ${user.email} created successfully`)}`);
        // res.status(201).json({message: `Username ${name} created successfully`});
    } catch(err) {
        console.error(err);
        res.status(500).json({
            error: 'Sign Up Failed',
            message: 'An unexpected error occurred'
        });
    }
    
});

//Sign In
router.post('/users/login', async (req, res) => {
    try {
        const email = req.body.email;
        const password = req.body.password;

        const [ user1 ] = await db.query(`SELECT id, email_id, password FROM users WHERE email_id = (?)`, [email] );
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

//Sign Out
router.post('/users/signout', (req, res) => {
    req.session.destroy((err) => {
        if(err) {
            return res.status(500).json({ error: "Sign Out Failed"});
        }

        res.sendStatus(200);
    });
});

function getUser(reqBody) {
    const user = {
        firstName: typeof reqBody.firstName === 'string' ? reqBody.firstName.trim() : '',
        lastName: typeof reqBody.lastName === 'string' ? reqBody.lastName.trim() : '',
        email: typeof reqBody.email === 'string' ? reqBody.email.trim().toLowerCase() : '',
        password: typeof reqBody.password === 'string' ? reqBody.password : ''
    }

    return user;
}

function validateUserInput(user) {
    if (!user.firstName) {
        return 'First name is required';
    }


    if (!user.email) {
        return 'Email is required';
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(user.email)) {
        return 'Please enter a valid email address';
    }

    if (!user.password || user.password.length < 8) {
        return 'Password must be at least 8 characters long';
    }

    return null;
}

module.exports = router;