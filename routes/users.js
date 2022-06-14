const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

const mailer = require("./mailer");

const {v4: uuidv4} = require("uuid");

// Load User model
const User = require('../models/User');

const Token = require("../models/tokens");

const { forwardAuthenticated } = require('../config/auth');

// Login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));

// Register
router.post('/register', (req, res) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (password != password2) {
    errors.push({ msg: 'Passwords do not match' });
  }

  if (password.length < 6) {
    errors.push({ msg: 'Password must be at least 6 characters' });
  }

  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2
    });
  } else {
    User.findOne({ email: email }).then(user => {
      if (user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2
        });
      } else {
        const userId = uuidv4();

        const newUser = new User({
          name,
          email,
          password,
          userId
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then(async(user) => {
                // req.flash(
                //   'success_msg',
                //   'You are now registered and can log in'
                // );
                // res.redirect('/users/login');
                // -----------------------------------
                // SEND AN VERIFICATION LINK
                const hostUrl = req.headers.host;
                console.log(hostUrl);
                await mailer.sendAnEmail(hostUrl, user.email, userId);
                
                
                //---------------------------------------------------------------
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
  }
});


// -----------------------------------------------------------------------------------
// Token Verification
// /user/verify/c2a6f28b-20e7-4b87-83eb-ba396e31167f/7d109fe546e8854b7e8e4c49cba2def6
router.get("/verify/:userId/:token", async(req, res) => {
  const { userId, token} = req.params;
  console.log(userId + "\n" + token);
  // res.send("Hello")
  // console.log(_id, token);
  // Below returns an array of all the Entries...
  Token.find({userId}).then((results) => {
    if(results.length > 0){ // we got some
      // checkin if the tokens have expired
      const {expiresAt, uniqueToken} = results[0];
      if(expiresAt < Date.now()){
          // Token No longer valid
          Token.deleteOne({userId}).then(() => {
            // Delete the user also who has registered but failed to verify themselves
            User.deleteOne({userId}).then(() => {
              let message = "Link has expired. Please Sign up again !!"
            })
            console.log(("The Invalid Token deleted successfully!!"));
          }).catch(e => {
            // error occuring during the deletion of invalid token
            console.log(e);
          })
      } else {
        // The Link is still active
        // Comparing the hashed token in db
        bcrypt.compare(token, uniqueToken).then((result) => {
          if(result){
            // Token matched
            User.updateOne({userId}, {isVerified: true}).then(() => {
              Token.deleteOne({userId}).then(() => {
                res.redirect("/users/verified")
              }).catch(e => {
                let message = "Error while deleting the verified Token !!"
                console.log(e);
              })
            }).catch(e => {
              let message = "An error occurred during updating the DB"
              console.log(e);
            }) 
          } else {
            let message = "Broken Link. Please follow the Link provided again !!"
            console.log(message);
          }
        }).catch(e => {
          console.log(e);
        })
      }


    } else {
      // No records exist for the userId
      let msg = {msg: "Account record does not exist or has been verified already ! Please Sign up or Log in to proceed !!"}

    }
  }).catch(e => {
    console.log(e);
  })
});

router.get("/verified", (req, res) => {
  // res.render("verified");
  res.send("Verified !!!")
})

// Login
router.post('/login', async(req, res, next) => {
  const userDetails = await User.findOne({email});

  if(!(userDetails.isVerified)){
    let message = "User has not been verified, Please follow the link for verification"
  } else {
      passport.authenticate('local', {
      successRedirect: '/dashboard',
      failureRedirect: '/users/login',
      failureFlash: true
    })(req, res, next);
  }
});

// Logout
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

module.exports = router;
