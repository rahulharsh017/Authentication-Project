import UserModel from "../models/user.model.js";
import bcrypt from "bcrypt";
import sendEmailVerificationOTP from "../utils/sendEmailVerificationOTP.js";
import EmailVerificationModel from "../models/emailVerification.js";
class UserController{

    //User Registration
    static userRegistration = async (req,res) =>{
        try {
             const {name,email,password,password_confirmation} = req.body;

             if(!name || !email || !password || !password_confirmation){
                 return res.status(400).json({status:"failed",message:"All fields are required"});
             }

             if(password !== password_confirmation){
                 return res.status(400).json({status:"failed",message:"Password do not match"});
             }
             const existingUser = await UserModel.findOne({email:email});
             if(existingUser){
                 return res.status(400).json({status:"failed",message:"Email already exists"});
             }
             const salt = await bcrypt.genSalt(Number(process.env.SALT));
             const hashedPassword = await bcrypt.hash(password,salt);
             const newUser = await new UserModel({
                 name,
                 email,
                 password:hashedPassword
             }).save();

             sendEmailVerificationOTP(req,newUser);

             return res.status(201).json(
                {status:"success",
                    message:"User Registered Successfully",
                user:{id:newUser._id,name:newUser.name,email:newUser.email}});
            
        } catch (error) {
            console.log(error);
            res.status(500).json({status:"failed",message:"Unable to Resgister, please try again later"});
            
        }
    }
    //User Email Verification
    static verifyEmail = async (req,res) =>{
        try {
            const {email,otp} = req.body;

            if(!email || !otp){
                return res.status(400).json({status:"failed",message:"All fields are required"});
            }

            const existingUser = await UserModel.findOne({email:email});
            if(!existingUser){
                return res.status(400).json({status:"failed",message:"Email does not exist"});
            }

            if(existingUser.is_verified){
                return res.status(400).json({status:"failed",message:"Email already verified"});
            }

            const emailVerification = await EmailVerificationModel.findOne({userId:existingUser._id,otp:otp});
            if(!emailVerification){
                if(!existingUser.is_verified){
                    await sendEmailVerificationOTP(req,existingUser);
                    return res.status(400).json({status:"failed",message:"Invalid OTP, new OTP sent"});
                }
                return res.status(400).json({status:"failed",message:"Invalid OTP"});
            }
            
            const currentTime = new Date();
            const expirationTime = new Date(emailVerification.createdAt.getTime() + 15*60000);
            if(currentTime > expirationTime){
                await sendEmailVerificationOTP(req,existingUser);
                return res.status(400).json({status:"failed",message:"OTP expired, new OTP sent"});
            }

            existingUser.is_verified = true;
            await existingUser.save();

            await EmailVerificationModel.deleteOne({userId:existingUser._id,otp:otp});

            return res.status(200).json({status:"success",message:"Email verified successfully"}); 
        } catch (error) {
            console.log(error);
            res.status(500).json({status:"failed",message:"Unable to verify email, please try again later"});
            
        }
    }
}

export default UserController;