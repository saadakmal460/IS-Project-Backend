const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const User = require("../../models/User/User");

const userController = {
    //Register a new user
    register: asyncHandler(async (req, res) => {
        const { username, email, password } = req.body;
        //const userFound = await User.findOne({ username, email }); //Old Error Logic 
        const userFound = await User.findOne({
            $or: [{ username }, { email }]
        });
        if (userFound) {
            throw new Error("User already exists");
        }
        //Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        //register the user
        const userRegistered = await User.create({
            username,
            email,
            password: hashedPassword,
        });
        //send the response
        res.status(201).json({
            status: 'success',
            message: "User registered successfully",
        });
    }),
    //Login a user
    login: asyncHandler(async (req, res, next) => {
        passport.authenticate('local', (err, user, info) => {
            if (err) {
                return next(err);
            }
            //If user not found
            if (!user) {
                return res.status(401).json({
                    message: info.message
                });
            }

            //send the response
            res.json({
                status: 'success',
                message: "Login Successfull",
                username: user?.username,
                email: user?.email,
                role: user?.user_role,
                mfa: "yes",
                _id: user?._id
            })
        })(req, res, next);
    }),

    //Google Auth
    googleAuth: passport.authenticate('google', { scope: ['profile', 'email'] }),
    //Google Auth Callback
    googleAuthCallback: asyncHandler(async (req, res, next) => {
        passport.authenticate('google', {
            failureRedirect: '/login',
            session: false,
        }, (err, user, info)=>{
            if(err){
                return next(err);
            }
            if(!user){
                return res.redirect('http://localhost:5173/google-login-error');
            }
            //Generate JWT token
            const token = jwt.sign({ id: user?._id }, process.env.JWT_SECRET, {
                expiresIn: '3d',
            });
            //set the token in the cookies
            res.cookie('token', token, {
                httpOnly: true,
                secure: false, //process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 24 * 60 * 60 * 1000, //1 day
            });
            //redirect to the home page
            res.redirect('http://localhost:5173/');
        })(req, res, next)
    }),

    //Check user authentication status
    checkAuthenticated: asyncHandler(async (req, res) => {
        const token = req.cookies['token']
        if (!token) {
            return res.status(401).json({
                isAuthenticated: false,
            })
        }
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET)
            //Find the user
            const user = await User.findById(decoded.id).select('-password')
            if (!user) {
                return res.status(401).json({
                    isAuthenticated: false,
                })
            } else {
                return res.status(200).json({
                    isAuthenticated: true,
                    _id: user?._id,
                    username: user?.username,
                    profilePicture: user?.profilePicture,
                    email: user?.email,
                })
            }
        }
        catch (error) {
            return res.status(401).json({
                isAuthenticated: false,
                error
            })
        }

    }),
}
module.exports = userController;