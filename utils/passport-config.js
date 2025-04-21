const passport = require("passport");
const User = require("../models/User/User");
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;

//Configuring the local strategy for passport

passport.use(
    new LocalStrategy({
        usernameField: 'username',  //username/email field
    }, async (username, password, done) => {
        try {
            //Find the user
            const user = await User.findOne({ username });
            //If user not found
            if (!user) {
                return done(null, false, {
                    message: 'No User found with this username'
                });
            }
            //If user found, check if password is correct
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                return done(null, user);
            } else {
                return done(null, false, {
                    message: 'Invalid Login Credentials'
                });
            }
        }
        catch (error) {
            return done(error);
        }
     })
)

module.exports = passport;