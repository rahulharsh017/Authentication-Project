import transporter from "../config/emailConfig.js";
import EmailVerificationModel from "../models/emailVerification.js";

const sendEmailVerificationOTP = async (req, user) => {
  const otp = Math.floor(1000 + Math.random() * 9000);

  await new EmailVerificationModel({ userId: user._id, otp }).save();

  const otpVerificationLink = `${process.env.FRONTEND_URL}/verify-email`;

  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: user.email,
    subject: "OTP - Verify your account",

    html: `<p>Dear ${user.name},</p><p>Thank you for signing up
with our website. To complete your registration, please
verify your email address by entering the following one-time

password (OTP): ${otpVerificationLink} </p>
<h2>OTP: ${otp}</h2>

<p>This OTP is valid for 15 minutes. If you didn't request
this OTP, please ignore this email.</p>`,
  });

  return otp;
};

export default sendEmailVerificationOTP;
