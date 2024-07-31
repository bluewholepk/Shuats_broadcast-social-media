require('dotenv').config();
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const mongoose = require('mongoose');
const passport = require('passport');
const flash = require('connect-flash');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;
const ObjectId = require('mongodb').ObjectId
const bcrypt = require('bcryptjs');
const methodOverride = require('method-override');
const expressSanitizer = require('express-sanitizer');
const requestIp = require('request-ip');
const moment = require('moment-timezone');
const dateIndia = moment.tz(Date.now(), "Asia/Kolkata")
const formidable = require('formidable');
const path = require('path');
const multer = require('multer');
const nodeMailer = require('nodemailer');
var fs = require('fs');


const Filter = require('bad-words');

const filter = new Filter();

filter.addWords('badwordsdetected');

const {
  ensureAuthenticated,
  forwardAuthenticated
} = {
  ensureAuthenticated: function(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    req.flash('error_msg', "Login First [Without login you can't access.]");
    res.redirect('/');
  },
  forwardAuthenticated: function(req, res, next) {
    if (!req.isAuthenticated()) {
      return next();
    }
    res.redirect('/posts');
  }
};

const app = express();

app.use(express.static("./public/"));
app.use(expressLayouts);
app.set('view engine', 'ejs');
app.use(express.json());
app.use(expressSanitizer());

// Express body parser
app.use(express.urlencoded({
  extended: true
}));

// Express session
app.use(
  session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Connect flash

app.use(flash());

// Global variables
app.use(function(req, res, next) {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

app.use(methodOverride(function(req, res) {
  if (req.body && typeof req.body === 'object' && '_method' in req.body) {
    var method = req.body._method;
    delete req.body._method;
    return method;
  }
}));

//MongoDb connection
mongoose.connect('mongodb://localhost/ShuatsBraodcastDB', { useNewUrlParser: true, useUnifiedTopology: true ,useFindAndModify: false})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

//mongoose.connect("mongodb+srv://admin-prashant:prashant1601@cluster0.fpopc.mongodb.net/NewHorizonDB", {useNewUrlParser: true,useUnifiedTopology: true,useFindAndModify: false})


//user Schema

const UserSchema = new mongoose.Schema({
  fname: {type: String,required: true},
  gender: {type: String,required: false},
  email: {type: String,required: true},
  password: {type: String,required: true},
  date: {type: Date,default: Date.now},
  dob: {type: String,/* required: true*/},
  phone: {type: String,/*required:true*/},
  prof: {type: String,default: ''},
  about: {type: String,default: ''},
  address: {type: String,default: 'Address Not Field.'},
  ip: {type: String},
  backup: {type: String},
  userImage: {type: String,default: 'default.png'},
  isVerified: { type: Boolean, default: false },

  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],

});


const verificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  token: String,
});

var imageSchema = new mongoose.Schema({
  fname : String,
  email: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  userImage: {type: String},
  desc:  {type: String},
  img:{data: Buffer,contentType: String,default:''},
  createdAt: {type: Date,default: Date.now},
  timeDifference: {type: String}

  // date: {type: Date.now()}
});

const User = mongoose.model('User', UserSchema);
const Verification = mongoose.model('Verification', verificationSchema);
const imgModel = mongoose.model('Image', imageSchema);





passport.use(
  new LocalStrategy(
    {
      usernameField: 'email',
    },
    async (email, password, done) => {
      try {
        // Match user
        const user = await User.findOne({
          email: email.toLowerCase() + "@shiats.edu.in",
        }).exec();

        if (!user) {
          return done(null, false, {
            message: 'Sorry! You are not registered. Please register and try again.',
          });
        }
       
        if (user && user.isVerified) {
          // Match password
          const isMatch = await bcrypt.compare(password, user.password);

          if (isMatch) {
            return done(null, user);
          } else {
            return done(null, false, {
              message: 'Password incorrect.',
            });
          }
        } else {
          return done(null, false, {
            message: 'Your account is not verified. Please check your Institute Email for verification instructions.',
          });
        }
      } catch (error) {
        return done(error); // Handle database query or bcrypt error
      }
    }
  )
);

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


app.get('/verify', async (req, res) => {
  const token = req.query.token;

  const verification = await Verification.findOne({ token });

  if (verification) {
    const user = await User.findById(verification.userId);
    user.isVerified = true;
    await user.save();
    res.render('verification-success', { success: true });
  } else {
    res.render('verification-fail', { success: false });
  }
});

//Landing page
app.get('/', forwardAuthenticated, (req, res) => res.render('welcome.ejs'));


// profile
app.get('/profile', ensureAuthenticated, (req, res) =>res.render('profile', {user: req.user}));



//team
app.get('/team', ensureAuthenticated, (req, res) =>
  res.render('team', {
    user: req.user
  })
);

//About
app.get('/about', ensureAuthenticated, (req, res) =>
  res.render('about', {
    user: req.user
  })
);



app.post('/register', (req, res) => {
  const {fname,password,backup} = req.body;
  const email = req.body.email.toLowerCase();
  const ip = requestIp.getClientIp(req);
  let errors = [];

  if (!fname || !email || !password || !backup) {
    errors.push({
      msg: 'Please enter all fields.'
    });
  }

  if (password != backup) {
    errors.push({
      msg: 'Passwords do not match.'
    });
  }

  if (password.length < 6) {
    errors.push({
      msg: 'Password must be at least 6 characters.'
    });
  }

  if (errors.length > 0) {
    res.render('welcome', {
      errors,fname,email,password,backup,ip
    });
  } else {
    User.findOne({
      email: email.toLowerCase() + "@shiats.edu.in"
    }).then(user => {
      if (user) {
        errors.push({
          msg: 'You are already registered. Please login'
        });
        res.render('welcome', {
          errors,fname,email,password,backup,ip
        });
      } else {
        const newUser = new User({
          fname,email: email.toLowerCase() + "@shiats.edu.in",password,backup,ip
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser.save().then(user => {
              req.flash(
                'success_msg',
                'Check Your Email Sent by SHUATS BROADCAST for Account Verification.'
              );
              const nodemailer = require('nodemailer');

              // Create a transporter for nodemailer
              let transporter = nodemailer.createTransport({
                host: "smtp.gmail.com",
                port: 465,
                secure: true,
                tls: {
                  rejectUnauthorized: false,
                },
                auth: {
                  // user: process.env.USER_EMAIL,
                  // pass: process.env.USER_PASSWORD,
                  user: 'shuatsbroadcast@gmail.com',
                  pass: 'apgq hgyy iefs fatz',
                }
              });

              // Send verification email
              const verificationToken = Math.random().toString(36).substring(7);

              const newVerification = new Verification({
                userId: newUser._id,
                token: verificationToken,
              });

              newVerification.save().then(() => {
                const mailOptions = {
                  from: 'shuatsbroadcast@gmail.com',
                  to: newUser.email,
                  subject: 'Account Verification',
                  text: `Click the following link to verify your account: http://localhost:3000/verify?token=${verificationToken}`,
                };

                transporter.sendMail(mailOptions, (error, info) => {
                  if (error) {
                    return console.log(error);
                  }
                  console.log('Message %s sent: %s', info.messageId, info.response);
                  res.redirect('/');
                });
              }).catch(err => console.log(err));
            }).catch(err => console.log(err));
          });
        });
      }
    });
  }
});


// Login
app.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/posts',
    failureRedirect: '/',
    failureFlash: true
  })(req, res, next);
});

// Logout
app.get('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    req.flash('success_msg', 'You are logged out Successfully ! ');
    res.redirect('/');
  });
});

// SHOW EDIT USER FORM
app.get('/edit/(:id)', ensureAuthenticated, function(req, res, next) {
  var o_id = new ObjectId(req.params.id)
  User.find({
    "_id": o_id
  }, (function(err, result) {
    if (err) return console.log(err)

    // if user not found
    if (!result) {
      req.flash('error', 'User not found with id = ' + req.params.id)
      res.redirect('/profile')
    } else { // if user found
      // render to views/user/edit.ejs template file
      res.render('edit', {
        title: 'Edit User',
        //data: rows[0],
        id: result[0]._id,
        fname: result[0].fname,
        lname: result[0].lname,
        gender: result[0].gender,
        dob: result[0].dob,
        phone: result[0].phone,
        address: result[0].address,
        userImage: result[0].userImage,
        prof: result[0].prof,
        about: result[0].about
      })
    }
  }))
})

// EDIT USER POST ACTION
app.put('/edit/(:id)', ensureAuthenticated, function(req, res, next) {

  const o_id = new ObjectId(req.params.id)
  User.updateOne({
    "_id": o_id
  }, {
    $set: {
      fname: req.body.fname,
      lname: req.body.lname,
      gender: req.body.gender,
      dob: req.body.dob,
      phone: req.body.phone,
      address: req.body.address,
      prof: req.body.prof,
      about: req.body.about

    }
  }, function(err, result) {
    if (err) {
      req.flash('error', err)

      res.render('edit', {
        id: req.params.id,
        fname: req.body.fname,
        lname: req.body.lname,
        gender: req.body.gender,
        dob: req.body.dob,
        phone: req.body.phone,
        address: req.body.address,
        prof: req.body.prof,
        about: req.body.about

      })

    } else {
      req.flash('success_msg', 'Profile updated successfully!')
      res.redirect('/profile');
    }
  });
})





// app.get('/search', ensureAuthenticated, (req, res) => {
//   try {

//     User.find({
//         $and: [{
//             email: {
//               '$regex': req.query.worksearch
//             }
//           },
//           {
//             pincode: {
//               '$regex': req.query.pinsearch
//             }
//           },
//           {
//             address: {
//               '$regex': req.query.freesearch
//             }
//           },
//           {
//             status: {
//               '$regex': "Active"
//             }
//           }
//         ]
//       },
//       (err, user) => {
//         if (err) {
//           req.flash('error', ' Worng Input .')
//           res.redirect('/services');
//           console.log(err);
//           console.log('Finding book');
//         } else {
//           res.render('result', {
//             user: user
//           })
//         }
//       })
//   } catch (error) {
//     console.log(error);
//   }
// });

// app.get('/search', ensureAuthenticated, async (req, res) => {
//   try {
//     const { worksearch, pinsearch, freesearch } = req.query;

//     const users = await User.find({
//       email: { $regex: email },
//       fname: { $regex: fname }
     
//     }).exec();

//     res.render('result', { user: users });
//   } catch (error) {
//     console.error(error);
//     req.flash('error', 'Wrong Input.');
//     res.redirect('/posts');
//   }
// });


app.get("/users/:userId", ensureAuthenticated, function(req, res) {

  const requestedUserId = req.params.userId;

  User.findOne({
    _id: requestedUserId
  }, function(err, user) {
    res.render("post", {
      user: req.user,

      fname: user.fname,
      email: user.email,
      gender: user.gender,
      phone: user.phone,
      address: user.address,
      prof: user.prof,
      about: user.about,
      userImage: user.userImage
    })
  })
});



// user profile
app.post('/profileImage', function(req, res) {
  var form = new formidable.IncomingForm();
  form.parse(req);
  let reqPath = path.join('./public/')
  let newfilename;
  form.on('fileBegin', function(name, file) {
    file.path = reqPath + '/upload/' + req.user.email + file.name;
    newfilename = req.user.email + file.name;
  });
  form.on('file', function(name, file) {
    User.findOneAndUpdate({
        email: req.user.email
      }, {
        'userImage': newfilename
      },
      function(err, result) {
        if (err) {
          req.flash('error_msg', "Profile Pitcute uploading failed.");
          res.redirect('/profile');
          console.log(err);
        }
      });
  });
  req.flash('success_msg', 'Your profile picture has been uploaded');
  res.redirect('/profile');
});


// DELETE USER
app.delete('/admin/delete/(:id)', ensureAuthenticated, function(req, res, next) {
  var o_id = new ObjectId(req.params.id)
  User.deleteOne({
    "_id": o_id
  }, function(err, result) {
    if (err) {
      req.flash('error', err)
      // redirect to users list page
      res.redirect('/admin-home')
    } else {
      req.flash('success', 'User deleted successfully! id = ' + req.params.id)
      // redirect to users list page
      res.redirect('/admin-home')
    }
  })
})



var storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads')
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname + '-' + Date.now())
  }
});

var upload = multer({ storage: storage });

app.get('/posts', ensureAuthenticated, (req, res) => {
  imgModel.find({}, (err, items) => {
      if (err) {
          console.log(err);
          res.status(500).send('An error occurred', err);
      } else {
          // Iterate through retrieved items and add a time difference property
          items.forEach(item => {
              item.timeDifference = getTimeDifference(item.createdAt); // Assuming 'createdAt' is the field storing creation time
          });

          res.render('imagesPage', { items: items, user: req.user });
      }
  });
});




// Function to replace bad words with asterisks

function replaceBadWordWithAsterisks(text, badWords) {
  let censoredText = text;
  badWords.forEach(word => {
    const regex = new RegExp(`\\b\\w*${word}\\w*\\b`, 'gi');
    censoredText = censoredText.replace(regex, '*'.repeat(word.length));
  });
  return censoredText;
}

app.post('/posts', upload.single('image'), ensureAuthenticated, (req, res) => {

  let descText = filter.clean(req.body.desc || ''); // Initialize descText with an empty string if req.body.desc is not defined

  // Array of bad words to detect
  const badWordsToDetect = ['microbadword']; // Replace with your bad words

  // Replace detected bad words with asterisks in the description
  const censoredDesc = replaceBadWordWithAsterisks(descText, badWordsToDetect);

  let obj = {
      fname: req.user.fname,
      userImage: req.user.userImage,
      userId:req.user._id,
      email: req.user.email,
      desc: censoredDesc,    
  };
    
  if (req.file) {
      obj.img = {
          data: fs.readFileSync(path.join(__dirname, '/uploads/', req.file.filename)),
          contentType: 'image/png'
      };
  }

  imgModel.create(obj, (err, item) => {
      if (err) {
          console.log(err);
          res.status(500).send('An error occurred', err);
      } else {
          res.redirect('/posts');
      }
  });
});



let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function() {
  console.log("server has started on port localhost:3000.");
});



// Function to calculate time difference
function getTimeDifference(createdAt) {
  const now = moment(); // Get the current time
  const postTime = moment(createdAt); // Convert the post's creation time to a moment object

  const duration = moment.duration(now.diff(postTime)); // Calculate the duration/difference

  const days = duration.asDays();
  const hours = duration.asHours();
  const minutes = duration.asMinutes();

  if (days >= 1) {
      return `${Math.floor(days)} day${Math.floor(days) !== 1 ? 's' : ''} ago`;
  } else if (hours >= 1) {
      return `${Math.floor(hours)} hour${Math.floor(hours) !== 1 ? 's' : ''} ago`;
  } else {
      return `${Math.floor(minutes)} minute${Math.floor(minutes) !== 1 ? 's' : ''} ago`;
  }
}