var FacebookStrategy = require('passport-facebook').Strategy;

// load up the user model
var User = require('../app/models/user');

// load up the auth variables from our auth module
var configAuth = require('./auth');

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

  // === FACEBOOK ===
  passport.use(new FacebookStrategy({
      // load in our auth module info
      clientID     : configAuth.facebookAuth.clientID,
      clientSecret : configAuth.facebookAuth.clientSecret,
      callbackURL  : configAuth.facebookAuth.callbackURL,
      profileFields : ['id', 'name', 'picture.type(large)', 'emails', 'displayName', 'gender']
    },
    // facebook will send back the token and profile
    function(token, refreshToken, profile, done){

      process.nextTick(function(){
        console.log(profile);
        User.findOne({ 'facebook.id' : profile.id }, function(err, user){

          if (err)
            return done(err);

          if (user){
            return done(null, user); // return user if found note: opposite order of local
          }

          var newUser = new User();
          newUser.facebook.id = profile.id;
          newUser.facebook.token = token;
          newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
          newUser.facebook.email = profile.emails[0].value;
          newUser.facebook.photos = profile.photos[0].value;
          newUser.facebook.gender = profile.gender;

          newUser.save(function(err){
            if(err)
              throw err;

            return done(null, newUser);
          });
        });
      });
    }));
};
