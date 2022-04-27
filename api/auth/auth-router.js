const router = require("express").Router();
const jwt = require('jsonwebtoken')
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const User = require('../users/users-model')
const bcrypt = require('bcryptjs')

router.post("/register", validateRoleName, (req, res, next) => {

  let user = req.body
  const hash = bcrypt.hashSync(user.password, 8)
  user.password = hash

  User.add(user)
    .then(saved => {
      res.status(201).json(saved)
    })
    .catch(next) 
})
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */



router.post("/login", checkUsernameExists, (req, res, next) => {
  if (bcrypt.compareSync(req.body.password, req.user.password)) {
    const token = buildToken(req.user)
    res.json({
      message: `${req.user.username} is back!`,
      token,
    })
  } else {
    next({ status: 401, message: 'Invalid credentials' })
  }
  // let { username, password } = req.body

  // User.findBy({ username })
  //   .then(([user]) => {
  //     if (user && bcrypt.compareSync(password, user.password)) {
  //       res.status(200).json(
  //         { message: `${user.username} is back!`, 
  //         token: buildToken(user)

  //        })
  //     } else {
  //       next({ status: 401, message: 'Invalid Credentials' })
  //     }
  //   })
  //   .catch(next)
  
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    
});

function buildToken(user){
  const payload= {
    subject: user.user_id, 
    username: user.username, 
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}


module.exports = router;
