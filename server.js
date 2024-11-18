if(process.env.NODE_ENV !== 'production'){
    require('dotenv').config()
}

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const override = require('method-override')
const FacebookStrategy = require('passport-facebook').Strategy

const initializePassword = require('./passport.js');
initializePassword(
    passport, 
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id )
)

const users = [];
var user = {};
passport.serializeUser(function (user, done) {
    done(null, user);
});
passport.deserializeUser(function (id, done) {
    done(null, user);
});

var facebookAuth = {
    'clientID' : '1284767246284093',
    'clientSecret' : 'ee5a6aa63a30742c37146e4a27dd3187',
    'callbackURL' : 'http://localhost:8099/auth/facebook/callback'
}

passport.use(new FacebookStrategy({
    "clientID"        : facebookAuth.clientID,
    "clientSecret"    : facebookAuth.clientSecret,
    "callbackURL"     : facebookAuth.callbackURL
  },  
  function (token, refreshToken, profile, done) {
    console.log("Facebook Profile: " + JSON.stringify(profile));
    console.log(profile);
    user = {};
    user['id'] = profile.id;
    user['name'] = profile.displayName;
    user['type'] = profile.provider; 
    console.log('user object: ' + JSON.stringify(user));
    return done(null,user); 
  })
);

app.use(express.static('public')); 
app.use(express.urlencoded({extended: false}))
app.set('views', './public/views');
app.set('view engine', 'ejs');
app.use(flash());
app.use(override('_method'))
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())

app.get('/', checkNotAuthenticated, (req, res) => {
	res.render('login.ejs');
})

app.get("/auth/facebook", passport.authenticate("facebook", { scope : "email" }));
app.get("/auth/facebook/callback",
    passport.authenticate("facebook", {
        successRedirect : "/hello",
        failureRedirect : "/"
}));

app.get('/hello', checkAuthenticated, (req, res) => {
	res.render('hello.ejs', {name: req.user.name});
})

app.get('/login', checkNotAuthenticated, (req, res) => {
	res.render('login.ejs');
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local',{
    successRedirect: '/hello',
    failureRedirect: '/login',
    failureFlash: true
}))

app.get('/register', checkNotAuthenticated, (req, res) => {
	res.render('register.ejs');
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try{
        const hashPassword = await bcrypt.hash(req.body.password, 10);
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashPassword
        })
        res.redirect('/login')
    } catch {
        res.redirect('/register')
    }
    console.log(users)
})

app.delete('/logout', (req, res, next) => {
  req.logOut(err => {
    if(err)
        return next(err);
  })
  res.redirect('/login')
})

function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
     return next()
    }   
    res.redirect('/login')
}

function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
     return res.redirect('/hello')
    }   
    next()
}


const port = process.env.PORT || 8099;
app.listen(port, () => {console.log(`Listening at http://localhost:${port}`);});
