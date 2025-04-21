require('dotenv').config();

const cors = require("cors");
const passport = require("./utils/passport-config")
const express = require("express");
const connectDB = require("./utils/connectDB");
const usersRouter = require('./router/user/usersRouter');

//call the db
connectDB();

const app = express();

//Port
const PORT = 5000

// Middlewares
app.use(express.json()); 
const corsOptions = {
    origin: ['http://localhost:5173'],
    credentials: true,
};
app.use(cors(corsOptions));

//Passport middleware
app.use(passport.initialize());

//Routes
app.use("/api/v1/users", usersRouter);

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