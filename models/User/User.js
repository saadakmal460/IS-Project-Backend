const mongoose = require("mongoose");

const userSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: false,
    },
    password: {
        type: String,
        required: false,
    },
    googleId: {
        type: String,
        required: false,
    },
    authMethod: {
        type: String,
        enum: ["local", "google","facebook", "github"],
        required: true,
        default: "local",
    },
    lastLogin: {
        type: Date,
        default: Date.now,
    },
}   , { timestamps: true }
);

const User = mongoose.model("User", userSchema);
module.exports = User;  