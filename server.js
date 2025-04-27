require('dotenv').config();

const cors = require("cors");
const passport = require("./utils/passport-config")
const express = require("express");
const cookieParser = require("cookie-parser");
const connectDB = require("./utils/connectDB");
const usersRouter = require('./router/user/usersRouter');
const {globalLimiter} = require('./utils/RateLimiter')
const logMiddleware = require("./Middleware/Logger");
const fileUpload = require('express-fileupload');


//call the db

connectDB();

const app = express();

//Port
const PORT = 5000

// Middlewares
const corsOptions = {
    origin: ['http://localhost:5173'],
    credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json()); 



app.use(globalLimiter)
app.use(fileUpload());
//Passport middleware

app.use(passport.initialize());
app.use(logMiddleware);
app.use(cookieParser()) //for parsing cookies automatically

//Routes
// app.get('/' ,(req, res) => {
//     res.status(200).json('yes')
// });


app.use("/api/v1/users", usersRouter);
app.use("/api/security", require('./router/Security/Security'));
app.use("/api/crypto", require('./router/Crypto/cryptoRoutes'));
app.use("/api/model", require('./router/Summarizer/ModelRoutes'));




//Not Found
app.use((req, res, next) => {
    res.status(404).json({message: "Route not found on server"});
});


//Error handling middleware
app.use((err, req, res, next) => {
    const message = err.message
    const stack = err.stack
    res.status(500).json({
        message,
        stack
    });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});