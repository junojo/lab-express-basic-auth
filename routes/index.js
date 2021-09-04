const { Router } = require('express');
const User = require('./../models/user');
const bcryptjs = require('bcryptjs');
const routeGuardMiddleware = require('./../middleware/route-guard');

const router = Router();

// All requests
router.get('/', (req, res, next) => {
  res.render('index');
});

// Register
router.get('/register', (req, res, next) => {
  res.render('register');
});

router.post('/register', (req, res, next) => {
  const { name, email, password } = req.body;
  // make sure users fill all mandatory fields:
  if (!name || !email || !password) {
    res.render('register', {
      errorMessage:
        'All fields are mandatory. Please provide your username, email and password.'
    });
    return;
  }
  bcryptjs
    .hash(password, 10)
    .then((passwordHashAndSalt) => {
      return User.create({
        name,
        email,
        passwordHashAndSalt
      });
    })
    .then((user) => {
      console.log('New user created', user);
      // Serialing the user
      req.session.userId = user._id;
      res.redirect('/');
    })
    .catch((error) => {
      next(error);
    });
});

// Log In
router.get('/log-in', (req, res, next) => {
  res.render('log-in');
});

router.post('/log-in', (req, res, next) => {
  const { email, password } = req.body;
  let user;
  User.findOne({ email })
    .then((document) => {
      user = document;
      if (!user) {
        throw new Error('ACCOUNT_NOT_FOUND');
      } else {
        return bcryptjs.compare(password, user.passwordHashAndSalt);
      }
    })
    .then((comparisonResult) => {
      if (comparisonResult) {
        console.log('User was authenticated');
        req.session.userId = user._id;
        res.redirect('/');
      } else {
        throw new Error('WRONG_PASSWORD');
      }
    })
    .catch((error) => {
      next(error);
    });
});

// Log Out
router.post('/log-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

// Private Pages
router.get('/private', routeGuardMiddleware, (req, res, next) => {
  res.render('private');
});

module.exports = router;
