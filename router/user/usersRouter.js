const express = require('express');
const userController = require('../../controllers/users/userController');
const { generateAndSendOtp, verifyOtp, verifyOtpAtLogin } = require('../../controllers/Auth/OTP');

const usersRouter = express.Router();   

//Register a new user
usersRouter.post("/register", userController.register);
//login a user
usersRouter.post("/login", userController.login);


usersRouter.post("/sendOtp", generateAndSendOtp);

usersRouter.post("/verifyOtp", verifyOtp);

usersRouter.post("/loginOtp", verifyOtpAtLogin);




module.exports = usersRouter;