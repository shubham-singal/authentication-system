const express = require('express');
const app = express();
const port = 3000;
const db = require('./db');
const bcrypt = require('bcrypt');
const session = require('express-session');

function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).send('You must be logged in');
    }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'my-secret-key',
    resave: false,
    saveUninitialized: false
}));

app.get('/home.html', requireAuth, (req, res) => {
    res.sendFile(__dirname + '/public/home.html');
});

app.use(express.static('public', {
    index: false
}));





app.get('/users', async (req, res) => {
    try {
        const [ rows ]  = await db.query(`SELECT first_name, last_name, email_id FROM users`);
        res.status(200).json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error : err.message });
    }
    
});

app.get('/users/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const [ rows ] = await db.query(`SELECT first_name, email_id FROM USERS WHERE id = ?`, [id]);
        const row = rows[0];

        if(row == null || row == undefined) {
            res.status(200).json("User not found");
        } else {
            res.status(200).json({name: row.first_name, email: row.email_id});
        }
    } catch (err) {
        res.status(500).send();
    }
});

app.post('/users', async (req, res) => {

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

app.post('/users/login', async (req, res) => {
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

app.delete('/users/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const query = 'SELECT * FROM users WHERE id = ?';
        const [ result ] = await db.execute(query, [id]);

        if(result.affectedRows === 0) {
            return res.status(404).json( {message : 'User not found'});
        }
        
        await db.execute('DELETE FROM users WHERE id = ?', [id]);
        return res.status(200).json({message: `User ${id} deleted successfully` });

    } catch (err) {
        console.error(err.message);
        return res.status(500).json({message : err.message});
    }
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

app.listen(port, () => {
    console.log("App listening on port 3000");
})