const bcrypt = require("bcryptjs");
const OTP = require('../../models/OTP')
const generateOtp = require('../../Utils/GenerateOTP');
const { sendEmail } = require('../../utils/MailSetup');
const User = require('../../models/User/User');
const jwt = require("jsonwebtoken");



const generateAndSendOtp = async (req, res) => {
    const { email } = req.body;

    // Validate email
    if (!email || !/\S+@\S+\.\S+/.test(email)) {
        return res.status(400).json({ message: "Invalid email address" });
    }

    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + 3 * 60 * 1000); // OTP expires in 3 minutes

    try {
        // Hash the OTP before storing
        const hashedOtp = await bcrypt.hash(otp, 10);

        // Check if OTP already exists for this email
        const existingOtp = await OTP.findOne({ email: email });

        if (existingOtp) {
            existingOtp.otp = hashedOtp;
            existingOtp.expiresAt = expiresAt;
            await existingOtp.save();
        } else {
            const newOtp = new OTP({ email, otp: hashedOtp, expiresAt });
            await newOtp.save();
        }

        // Send OTP via email
        await sendEmail(email, 'Your OTP Code', `Your OTP code is: ${otp}`); // Send the plain OTP, not the hashed one

        return res.status(200).json({ message: "OTP sent successfully to your email" });
    } catch (error) {
        console.error("Error generating OTP:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
};

const verifyOtp = async (req, res) => {

    const { email, otp } = req.body;
    

    if (!email || !otp) {
        return res.status(400).json({ message: "Email and OTP are required." });
    }

    try {
        const existingOtp = await OTP.findOne({ email:email });

        if (!existingOtp) {
            return res.status(400).json({ message: "OTP not found. Request a new one." });
        }

        // Check if OTP is expired
        if (Date.now() > existingOtp.expiresAt) {
            return res.status(400).json({ message: "OTP expired. Request a new one." });
        }

        // Compare OTP with the hashed OTP in the database
        const isOtpValid = await bcrypt.compare(otp, existingOtp.otp);

        if (!isOtpValid) {

            return res.status(400).json({ message: "Invalid OTP." });
        }

        //OTP is valid, delete it from DB after verification

        const updatedUser = await User.findOneAndUpdate(
            { email: email },
            { $set: { isVerified: true } },
            { new: true }
        );


        if (!updatedUser) {
            return res.status(404).json({ message: "Employee not found" });
        }

        return res.status(200).json({ message: "OTP verified successfully!" });
    } catch (error) {
        console.error("Error verifying OTP:", error);
        return res.status(500).json({ message: "Internal server error." });
    }
};



const verifyOtpAtLogin = async (req,res)=>{
    const { email, otp } = req.body;



    if (!email || !otp) {
        return res.status(400).json({ message: "Email and OTP are required." });
    }

    try {
        const existingOtp = await OTP.findOne({ email:email });
        
        if (!existingOtp) {
            return res.status(400).json({ message: "OTP not found. Request a new one." });
        }

        

        // Check if OTP is expired
        if (Date.now() > existingOtp.expiresAt) {
            return res.status(400).json({ message: "OTP expired. Request a new one." });
        }

        // Compare OTP with the hashed OTP in the database
        const isOtpValid = await bcrypt.compare(otp, existingOtp.otp);

        if (!isOtpValid) {

            return res.status(400).json({ message: "Invalid OTP." });
        }
        


        const updatedUser = await User.findOneAndUpdate(
            { email: email },
            { $set: { isVerified: true } },
            { new: true }
        );

        const token = jwt.sign({ id: updatedUser?._id , role:updatedUser?.user_role }, process.env.JWT_SECRET , {
            expiresIn: process.env.JWT_LIFETIME,
        })
        //set the token into the cookie 
        res.cookie('token', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,  //1 day
        })

        if (!updatedUser) {
            return res.status(404).json({ message: "Employee not found" });
        }

        return res.status(200).json({ message: "OTP verified successfully!" , user:updatedUser , token:token });
    } catch (error) {
        console.error("Error verifying OTP:", error);
        return res.status(500).json({ message: "Internal server error." });
    }


}

module.exports = { generateAndSendOtp, verifyOtp , verifyOtpAtLogin };