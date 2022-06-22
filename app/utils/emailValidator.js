const emailValidator = require('deep-email-validator');

const isEmailValid = (email) => {
  return emailValidator.validate(email);
};

module.exports = isEmailValid;
