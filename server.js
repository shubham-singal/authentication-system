const express = require('express');
const app = express();
const port = 3000;
const db = require('./db');
const bcrypt = require('bcrypt');
const session = require('express-session');
const requireAuth = require('./middleware/authMiddleware');
const authRoutes = require('./routes/authRoutes');

app.use(express.json());

//parse request body
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false, //don't save session if unmodified
    saveUninitialized: false //don't create session until something stored
}));

app.get('/home.html', requireAuth, (req, res) => {
    res.sendFile(__dirname + '/public/home.html');
});

app.use(express.static('public', {
    index: false
}));

app.use(authRoutes);

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
            res.status(404).json("User not found");
        } else {
            res.status(200).json({name: row.first_name, email: row.email_id});
        }
    } catch (err) {
        res.status(500).send();
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


app.listen(port, () => {
    console.log("App listening on port 3000");
})