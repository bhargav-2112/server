/* eslint-disable no-unused-vars */
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const passportSetup = require('./app/passport');
const cookieSession = require('cookie-session');
const dbConfig = require('./app/config/db.config');

const app = express();

app.use(
    cookieSession({
      name: 'session',
      keys: ['xyz'],
      maxAge: 24 * 60 * 60 * 1000,
    }),
);

app.use(passport.initialize());
app.use(passport.session());

const corsOptions = {
  origin: 'http://localhost:8081',
  methods: 'GET, POST, PUT, DELETE',
  credentials: true,
};

app.use(cors(corsOptions));


// parse requests of content-type - application/json
app.use(express.json());

// parse requests of content-type - application/x-www-form-urlencoded
app.use(express.urlencoded({extended: true}));

const db = require('./app/models');
const Role = db.role;

db.mongoose
    .connect(`mongodb://${dbConfig.HOST}:${dbConfig.PORT}/${dbConfig.DB}`, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => {
      console.log('Successfully connect to MongoDB.');
      initial();
    })
    .catch((err) => {
      console.error('Connection error', err);
      process.exit();
    });

// simple route
app.get('/', (req, res) => {
  res.json({message: 'Welcome'});
});

// routes
require('./app/routes/auth.routes')(app);
require('./app/routes/user.routes')(app);

// set port, listen for requests
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});

// eslint-disable-next-line require-jsdoc
function initial() {
  Role.estimatedDocumentCount((err, count) => {
    if (!err && count === 0) {
      new Role({
        name: 'user',
      }).save((err) => {
        if (err) {
          console.log('error', err);
        }

        console.log('added \'user\' to roles collection');
      });

      new Role({
        name: 'moderator',
      }).save((err) => {
        if (err) {
          console.log('error', err);
        }

        console.log('added \'moderator\' to roles collection');
      });

      new Role({
        name: 'admin',
      }).save((err) => {
        if (err) {
          console.log('error', err);
        }

        console.log('added \'admin\' to roles collection');
      });
    }
  });
}
