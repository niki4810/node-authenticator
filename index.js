let express = require('express')
let morgan = require('morgan')
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let mongoose = require('mongoose')
let bcrypt = require('bcrypt')
let nodeifyit = require('nodeifyit')
let flash = require('connect-flash')
let User = require('./user')

mongoose.connect('mongodb://127.0.0.1:27017/authenticator')

// Add to top of index.js with other requires
let LocalStrategy = require('passport-local').Strategy

require('songbird')

const NODE_ENV = process.env.NODE_ENV
const PORT = process.env.PORT || 8000
const SALT = bcrypt.genSaltSync(10)

let app = express()

// And add the following just before app.listen
// Use ejs for templating, with the default directory /views
app.set('view engine', 'ejs')

// Read cookies, required for sessions
app.use(cookieParser('ilovethenodejs'))           
// Get POST/PUT body information (e.g., from html forms like login)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(flash()) 

// In-memory session support, required by passport.session()
app.use(session({
  secret: 'ilovethenodejs',
  resave: true,
  saveUninitialized: true
}))

// Use the passport middleware to enable passport
app.use(passport.initialize())

// Enable passport persistent sessions
app.use(passport.session())


passport.use(new LocalStrategy({
    // Use "email" field instead of "username"
    usernameField: 'email',
    failureFlash: true
}, nodeifyit(async (email, password) => {
   let user = await User.promise.findOne({email})
		
	if(!user) {				
		return [false, {message: 'Invalid username'}]
	}
	
   if (!await bcrypt.promise.compare(password, user.password)) {   	      		
       return [false, {message: 'Invalid password'}]
   }
 
   return user
}, {spread: true})))


passport.use('local-signup', new LocalStrategy({
	usernameField: 'email'},nodeifyit( async (email, password) => {
	email = (email || '').toLowerCase()
    // Is the email taken?
    if (await User.promise.findOne({email})) {
        return [false, {message: 'That email is already taken.'}]
    }

    // create the user
    let user = new User()
    user.email = email
    // Use a password hash instead of plain-text
    user.password = await bcrypt.promise.hash(password, SALT)
    return await user.save()
}, {spread: true})))

// Use email since id doesn't exist
passport.serializeUser(nodeifyit(async (user) => user.email))

passport.deserializeUser(nodeifyit( async (email) => { 
	return await User.findOne({email}).exec()
}))

// start server 
app.listen(PORT, ()=> console.log(`Listening @ http://127.0.0.1:${PORT}`))

// And add your root route after app.listen
app.get('/', (req, res) => {	
    res.render('index.ejs', {message: req.flash('error')})
})

function isLoggedIn (req, res, next) {
	if(req.isAuthenticated()) return next()
		res.redirect('/')
}

app.get('/profile', isLoggedIn, (req, res) => {	
	console.log("Cookies: ", req.cookies)
	let user = req.user;
	res.render('profile.ejs',{
		user: req.user
	})
})

// process the login form
app.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))

app.get('/logout', function(req, res) {
	req.logout()
	res.redirect('/')
})

app.post('/signup', passport.authenticate('local-signup', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))