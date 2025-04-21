const express = require('express');
const userController = require('../../controllers/users/userController');

const usersRouter = express.Router();   

//Register a new user
usersRouter.post("/register", userController.register);
//login a user
usersRouter.post("/login", userController.login);

module.exports = usersRouter;