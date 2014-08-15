// note: this is required before we initailize passport
// load all the things we need
var LocalStrategy = require('passport-local').Strategy;

// load up the user model
var User = require('../app/models/user');

// expose this function to our app using modules.exports
module.exports = function(passport){

  // === passport session setup ===
  // required for persistent login sessions
  // passport needs ability to serialize and unserialize users out of a session

  passport.serializeUser(function(user, done){
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
      done(err, user);
    });
  });

  // === local signup ===
  // use named strategies to have one for login and for signup
  // this will be used with `passport.authenticat('local-signup', {})`
  passport.use('local-signup', new LocalStrategy({
    // by default, LocalStrategy uses username and password. We override here
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true // allows us to pass back the entire request to the callback
  },
  function(req, email, password, done){

    // asynchronous
    // User.findOne wont fire unless data is sent back
    process.nextTick(function(){

      User.findOne({ 'local.email': email }, function(err, user){
        if(err)
          return done(err);

        // if user exists, send flash message
        if(user){
          return done(null, false, req.flash('signupMessage', 'That email is already taken'));
        } else {
          var newUser = new User();

          newUser.local.email = email;
          newUser.local.password = newUser.generateHash(password);

          newUser.save(function(err){
            if(err)
              throw err;
            return done(null, newUser);
          });
        }
      });
    });

  }));
};
