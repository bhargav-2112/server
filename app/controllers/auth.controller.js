const config = require('../config/auth.config');
const db = require('../models');
const User = db.user;
const Role = db.role;
const Token = db.token;
// eslint-disable-next-line no-unused-vars
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');
const verifyEmail = require('../utils/emailValidator');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

exports.signup = async (req, res) => {
  const user = new User({
    username: req.body.username,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8),
  });
  const {valid, reason, validators} = await verifyEmail(user.email);
  if (valid) {
    user.save((err, user) => {
      if (err) {
        res.status(500).send({message: err});
        return;
      }

      if (req.body.roles) {
        Role.find(
            {
              name: {$in: req.body.roles},
            },
            (err, roles) => {
              if (err) {
                res.status(500).send({message: err});
                return;
              }

              user.roles = roles.map((role) => role._id);
              user.save((err) => {
                if (err) {
                  res.status(500).send({message: err});
                  return;
                }

                res.send({message: 'User was registered successfully!'});
              });
            },
        );
      } else {
        Role.findOne({name: 'user'}, (err, role) => {
          if (err) {
            res.status(500).send({message: err});
            return;
          }

          user.roles = [role._id];
          user.save((err) => {
            if (err) {
              res.status(500).send({message: err});
              return;
            }

            res.send({message: 'User was registered successfully!'});
          });
        });
      }
    });
    const token = await new Token({
      userId: user._id,
      token: crypto.randomBytes(32).toString('hex'),
    }).save();
    console.log('token', token);
    // eslint-disable-next-line max-len
    const message = `${process.env.BASE_URL}/api/auth/verify/${user.id}/${token.token}`;
    await sendEmail(user.email, 'Verify Email', message);
  } else {
    return res.status(400).send({
      message: 'Please provide a valid email address.',
      reason: validators[reason].reason,
    });
  }
};

exports.signin = (req, res) => {
  User.findOne({
    username: req.body.username,
  })
      .populate('roles', '-__v')
      .exec((err, user) => {
        if (err) {
          res.status(500).send({message: err});
          return;
        }

        if (!user) {
          return res.status(404).send({message: 'User Not found.'});
        }

        const passwordIsValid = bcrypt.compareSync(
            req.body.password,
            user.password,
        );

        if (!passwordIsValid) {
          return res.status(401).send({
            accessToken: null,
            message: 'Invalid Password!',
          });
        }

        const token = jwt.sign({id: user.id}, config.secret, {
          expiresIn: 86400, // 24 hours
        });
        console.log('token', token);

        const authorities = [];

        for (let i = 0; i < user.roles.length; i++) {
          authorities.push('ROLE_' + user.roles[i].name.toUpperCase());
        }
        res.status(200).send({
          id: user._id,
          username: user.username,
          email: user.email,
          roles: authorities,
          accessToken: token,
        });
      });
};

exports.passswordResetLink = async (req, res) => {
  const user = await User.findOne({
    email: req.body.email,
  });

  if (!user) {
    return res.status(404).send({message: 'User Not found.'});
  }

  let token = await Token.findOne({userId: user._id});
  if (!token) {
    token = await new Token({
      userId: user._id,
      token: crypto.randomBytes(32).toString('hex'),
    }).save();
  }
  // eslint-disable-next-line max-len
  console.log('userId', user.id);
  console.log('token', token.token);
  // eslint-disable-next-line max-len
  const link = `${process.env.BASE_URL}/api/auth/pwd-reset/${user.id}/${token.token}`;
  await sendEmail(user.email, 'Reset Password', link);
  res.send({message: 'Password reset link has been sent to your email.',
    data: {
      id: user.id,
      token: token.token,
    }});
};
