require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const port = process.env.PORT || 3000;

const app = express();

const expireTime = 24 * 60 * 60 * 1000;

const saltRounds = 10;

app.use(express.static(__dirname + "/public"));

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}));

app.get('/', (req, res) => {
    var html = `
        <form action='/signUp' method='post'>
            <button>Sign Up</button>
        </form>
        <form action='/login' method='post'>
            <button>Log In</button>
        </form>
    `;

    if (req.query.loggedOut) {
        html += `<br> You have logged out`;
    }

    res.send(html);
});

// other pages here
app.post('/signUp', (req, res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;

    if (req.body.invalidCred) {
        html += '<br> invalid Credentials.';
    }

    res.send(html);
});

app.post('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;

    if (req.query.invalidEmail) {
        html += "<br>Invalid email";
    }
    if (req.query.noAccount) {
        html += "<br>No account found";
    }
    if (req.query.invalidPassword) {
        html += "<br>Wrong password";
    }
    res.send(html);
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required(),
            email: Joi.string().email({ maxDomainSegments: 2, tlds: { allow: ['com', 'net', 'ca'] } })
        });

    const validationResult = schema.validate({ username, password, email });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signUp?invalidCred=1");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, password: hashedPassword, email: email });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email({ maxDomainSegments: 2, tlds: { allow: ['com', 'net', 'ca'] } })
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect(308, "/login?invalidEmail=1");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect(308, "/login?noAccount=1");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.redirect(308, "/login?invalidPassword=1");
        return;
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login?noSession=1');
    }

    const images = ['alien_anguish.jpg',
        'alien_bug_eye.jpg',
        'alien_crying.jpg',
        'alien_huh.jpg',
        'alien_sad.jpg',
        'alien_sandwich.jpg',
        'alien_sitting.jpg',
        'alien_stupid.jpg',
        'alien_think_hard_crying.png'];

    var randomImage = Math.floor(Math.random() * images.length);

    var html = `
    Hello, ${req.session.username}!
    <img src='${images[randomImage]}' width='500' height='500'>
    <br>
    <form action='/logout' method='post'>
        <button>Log Out</button>
    </form>
    `;
    res.send(html);
});

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/?loggedOut=1');
});

// 404
app.use(function (req, res) {
    res.status(404).send("Page not found - 404");
});


app.listen(port, () => {
    console.log("Node application listening on port " + port);
});