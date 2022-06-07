import express from 'express'
import cookieParser from 'cookie-parser'
import logger from 'morgan'
import cors from 'cors'
import helmet from 'helmet'

import HttpError from './core/HttpError.js'
import indexRouter from './routes/index.js'

// TODO: Consider extracting most of this logic into createApp(routes, path) function so that
//   it can be used in unit tests to test each route individually.

const app = express()

app.use(helmet())
app.use(cors()) // TODO: Consider configuring CORS to be more restrictive, right now it allows all CORS requests.
app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())

// For Passport
import session from 'express-session';
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true }
}));

import passport from 'passport';
app.use(passport.initialize());
app.use(passport.authenticate('session'));

import prisma from './dbClient.js';
import { sign } from './core/auth.js';
import GoogleStrategy from 'passport-google-oauth2';

console.log('setting up Google');

passport.use(new GoogleStrategy.Strategy({
  clientID: process.env['GOOGLE_CLIENT_ID'],
  clientSecret: process.env['GOOGLE_CLIENT_SECRET'],
  callbackURL: 'http://localhost:3001/oauth2/redirect/google',
  scope: ['email'],
  passReqToCallback: true
}, async function (request, accessToken, refreshToken, profile, done) {
  let user = await prisma.user.findUnique({ where: { email: profile.email } });
  if (!user) {
    user = await prisma.user.create({ data: { email: profile.email, password: "password123!" } });
  }

  console.log(user.id);

  return done(null, user);
}));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

// Redirect user to Google
app.get('/login/federated/google', passport.authenticate('google'));

// Handle Google callback
app.get('/oauth2/redirect/google',
  passport.authenticate('google', {
    failureRedirect: 'http://localhost:3000/login',
    failureMessage: true
  }),
  async function(req, res) {
    const user = req.session.passport.user;
    console.log(user.id);
    const token = await sign(user.id);
    res.redirect('http://localhost:3000/login?token=' + token);
});

app.use('/', indexRouter)

// Custom error handler.
app.use((err, req, res, next) => {
  // As by expressjs documentation, when the headers have already
  // been sent to the client, we must delegate to the default error handler.
  if (res.headersSent) { return next(err) }

  if (err instanceof HttpError) {
    return res.status(err.statusCode).json({ message: err.message, data: err.data })
  }

  return next(err)
})

export default app
