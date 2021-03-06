var User = require('./models/user');

module.exports = function(app, passport){
  // HOME PAGE
  app.get('/', function(req, res){
    User.find(function(err, users) {
      res.render('index.ejs', { users: users});
    });
  });

  // LOGIN
  app.route('/login')
    .get(function(req, res){
      res.render('login.ejs', { message: req.flash('loginMessage')});
    })
    .post(passport.authenticate('local-login', {
      successRedirect : '/profile',
      failureRedirect : '/login',
      failureFlash: true
    }));

  // INITIAL SIGNUP

    // === local ===
      app.route('/signup')
        .get(function(req, res){
          res.render('signup.ejs', { message: req.flash('signupMessage') });
        })
        .post(passport.authenticate('local-signup', {
          successRedirect: '/profile', // this could instead be a callback
          failureRedirect: '/signup',
          failureFlash: true // allow flash messages
        }));

    // === facebook ===
      app.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' }));
      app.get('/auth/facebook/callback',
          passport.authenticate('facebook', {
            successRedirect : '/profile',
            failureRedirect : '/'
          }));

  // AUTHORIZING OTHER ACCOUNTS (LINKING)

    // === local ===
      app.route('/connect/local')
        .get(function(req, res){
          res.render('connect-local.ejs', { message: req.flash('loginMessage') });
        })
        .post(passport.authenticate('local-signup', {
          successRedirect : '/profile',
          failureRedirect : '/connect/local',
          failureFlash: true
        }));

    // === facebook ===
      app.get('/connect/facebook', passport.authorize('facebook', { scope: 'email' }));
      app.get('/connect/facebook/callback',
             passport.authorize('facebook', {
               successRedirect: '/profile',
               failureRedirect: '/'
             }))

  // UNLINK ACCOUNTS

    // === local ===
      app.get('/unlink/local', function(req, res){
        var user = req.user;
        user.local.email = undefined;
        user.local.password = undefined;
        user.save(function(err){
          res.redirect('/profile');
        });
      });
    // === facebook ===
      app.get('/unlink/facebook', function(req, res){
        var user = req.user;
        user.facebook.token = undefiend;
        user.save(function(err){
          res.redirect('/profile');
        });
      });

  // PROFILE
  app.get('/profile', isLoggedIn, function(req, res){
    res.render('profile.ejs', {
      user : req.user // get the user out of session and pass to template
    });
  });

  app.get('/logout', function(req, res){
    req.logout(); // provided by passport
    res.redirect('/');
  });

};

// middleware to make sure user is logged in
function isLoggedIn(req, res, next){
  // if user is authenticated in the session, next()
  if (req.isAuthenticated())
    return next();

  // if they aren't redirect
  res.redirect('/');
}
