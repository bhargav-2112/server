const {verifySignUp} = require('../middlewares');
const controller = require('../controllers/auth.controller');
const db = require('../models');
const sendEmail = require('../utils/sendEmail');
const User = db.user;
const Token = db.token;
const bcrypt = require('bcryptjs');

module.exports = function(app) {
  app.use(function(req, res, next) {
    res.header(
        'Access-Control-Allow-Headers',
        'x-access-token, Origin, Content-Type, Accept',
    );
    next();
  });

  // verify token
  app.get('/api/auth/verify/:id/:token', async (req, res) => {
    try {
      const user = await User.findOne({_id: req.params.id});
      if (!user) return res.status(400).send('Invalid link');

      const token = await Token.findOne({
        userId: user._id,
        token: req.params.token,
      });
      if (!token) return res.status(400).send('Invalid link');

      await User.updateOne({id: user._id, active: true});
      await Token.findByIdAndRemove(token._id);

      res.send('email verified sucessfully');
    } catch (error) {
      console.log('error', error);
      res.status(400).send('An error occured');
    }
  });

  // passsword reset link
  app.post('/api/auth/forgot-password', controller.passswordResetLink);

  // passsword reset
  // eslint-disable-next-line max-len
  app.post('/api/auth/pwd-reset/:id/:token', async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(400).send('invalid link or expired');

      const token = await Token.findOne({
        userId: user._id,
        token: req.params.token,
      });
      if (!token) return res.status(400).send('Invalid link or expired');

      user.password = bcrypt.hashSync(req.body.password, 8);

      await user.save();
      await token.delete();

      res.send({message: 'password reset sucessfully.'});
      // eslint-disable-next-line max-len
      await sendEmail(user.email, 'Reset Password', 'password reset sucessfully.');
    } catch (error) {
      res.send('An error occured');
      console.log(error);
    }
  });

  app.post(
      '/api/auth/signup',
      [
        verifySignUp.checkDuplicateUsernameOrEmail,
        verifySignUp.checkRolesExisted,
      ],
      controller.signup,
  );

  app.post('/api/auth/signin', controller.signin);
};
