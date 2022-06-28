/* eslint-disable max-len */
/* eslint-disable no-unused-vars */
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;

const GOOGLE_CLIENT_ID = '145756368477-9dm9q1ej0bm75qnh1bticlr2k9qi4nhf.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = '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';
const GITHUB_CLIENT_SECRET = 'e7cafc8a5f6a8bc9f376eb8c224a139812006b2b';
const GITHUB_CLIENT_ID = 'Iv1.446e33472d67b119';

passport.use(
    new GoogleStrategy(
        {
          clientID: GOOGLE_CLIENT_ID,
          clientSecret: GOOGLE_CLIENT_SECRET,
          callbackURL: '/auth/google/callback',
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, profile);
        },
    ),
);

passport.use(new GitHubStrategy({
  clientID: GITHUB_CLIENT_ID,
  clientSecret: GITHUB_CLIENT_SECRET,
  callbackURL: '/auth/github/callback',
},
function(accessToken, refreshToken, profile, done) {
  done(null, profile);
},
));
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});
