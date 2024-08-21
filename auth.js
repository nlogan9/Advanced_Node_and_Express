const passport = require('passport');
const LocalStrategy = require('passport-local');
const { ObjectID } = require('mongodb');
const GitHubStrategy = require("passport-github");
require('dotenv').config();
const bcrypt = require('bcrypt');

module.exports = function (app, myDataBase) {

  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/github/callback'
  },
    function(accessToken, refreshToken, profile, cb) {
      console.log(process.env.GITHUB_CLIENT_ID);
      UserActivation.findOrCreate({ githubID: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
));
    
  passport.use(new LocalStrategy((username, password, done) => {
    console.log("Username: ", username, " Password: ", password);
    myDataBase.findOne({ username: username }, (err, user) => {
      console.log(`User ${username} attempted to log in.`);
      if(err) return done(err);
      if (!user) return done(null, false);
      if (!bcrypt.compareSync(password, user.password)) return done(null, false);
      return done(null, user);
    })
  }));

  passport.serializeUser((user, done) => {
    done(null, user._id);
  });
    
  passport.deserializeUser((id, done) => {
    myDataBase.findOne({ _id: new ObjectID(id) }, (err, doc) => {
      done(null, doc);
    })
  });
    
}