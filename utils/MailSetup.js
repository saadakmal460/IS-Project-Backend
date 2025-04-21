const nodemailer = require('nodemailer');


const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com", // Ensure this is not '127.0.0.1'
    port: 587, 
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Send OTP email
const sendEmail = async (email , subject , text) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: subject,
        html: text,
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.log(error)
        throw new Error('Error sending OTP email');
    }
};

module.exports = {sendEmail}