module.exports = function(app, passport){
  // HOME PAGE
  app.get('/', function(req, res){
    res.render('index.ejs');
  });

  // LOGIN
  app.get('/login', function(req, res){
    // we will create loginMessage in our passport config
    res.render('login.ejs', { message: req.flash('loginMessage')});
  });

  // app.post('/login', fn)

  // SIGNUP
  app.get('/signup', function(req, res){
    res.render('signup.ejs', { message: req.flash('signupMessage') });
  });

  app.post('/signup', passport.authenticate('local-signup', {
    successRedirect: '/profile', // this could instead be a callback
    failureRedirect: '/signup',
    failureFlash: true // allow flash messages
  }));

  // PROFILE
  // we use our logged in middleware here
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
