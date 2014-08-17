module.exports = function(app, passport){
  // HOME PAGE
  app.get('/', function(req, res){
    res.render('index.ejs');
  });

  // PROFILE
  app.route('/profile')
    // we use our logged in middleware here
    .get(isLoggedIn, function(req, res){
      res.render('profile.ejs', {
        user : req.user // get the user out of session and pass to template
      });
    });

  // FACEBOOK ROUTES
  app.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' }));

  // facebook redirect
  app.get('/auth/facebook/callback',
      passport.authenticate('facebook', {
        successRedirect : '/profile',
        failureRedirect : '/'
      }));

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
