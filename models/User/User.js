const mongoose = require("mongoose");

const userSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
    },
    profilePicture: {
        type: Object,
        default: null,
    },
    email: {
        type: String,
        required: false,
    },
    password: {
        type: String,
        required: false,
    },
    user_role:{
        type:String,
        required:true,
        enum : ['user' , 'admin'],
        default : 'user'
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
    isVerified:{
        type:Boolean,
        default:false
    },
    lastLogin: {
        type: Date,
        default: Date.now,
    },
}   , { timestamps: true }
);

const User = mongoose.model("User", userSchema);
module.exports = User;  