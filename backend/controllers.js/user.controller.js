import UserModel from "../models/user.model.js";
import bcrypt from "bcrypt";
import sendEmailVerificationOTP from "../utils/sendEmailVerificationOTP.js";
import EmailVerificationModel from "../models/emailVerification.js";
import generateTokens from "../utils/generateTokens.js";
import setTokenCookies from "../utils/setTokenCookies.js";
import refreshAccessToken from "../utils/refreshAcessToken.js";
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

    //User Login
    static userLogin = async (req,res) =>{
        try {
            const{email,password} = req.body;

            if(!email || !password){
                return res.status(400).json({status:"failed",message:"All fields are required"});
            }

            const user = await UserModel.findOne({email});

            if(!user){
                return res.status(404).json({status:"Failed",message:"User not found"});
            }

            if(!user.is_verified){
                return res.status(400).json({status:"failed",message:"Your account is not verified"});
            }

            const isMatch = await bcrypt.compare(password,user.password);
            if(!isMatch){
                return res.status(401).json({status:"failed",message:"Invalid name or password"});
            }

            //Generate tokens
            const {accessToken,refreshToken,accessTokenExp,refreshTokenExp} = await generateTokens(user);

            //Set Cookies
            setTokenCookies(res,accessToken,refreshToken,accessTokenExp,refreshTokenExp);
            //Send Success Response with Tokens

            res.status(200).json({
                user:{id:user._id,email:user.email,name:user.name,
                roles:user.roles[0] },
                status:"success",
                message:"Login Successful",
                access_token:accessToken,
                refresh_token:refreshToken,
                access_token_exp:accessTokenExp,
                is_auth:true
            })
            
        } catch (error) {
            console.log(error);
            res.status(500).json({status:"failed",message:"Unable to login, please try again later"});
        }
    }

    // GET New Access Token or Refresh Token
    static getNewAccessToken = async (req,res) =>{
        try {
            
            const {newAccessToken,newRefreshToken,newAccessTokenExp,newRefreshTokenExp} = await refreshAccessToken(req,res);
            setTokenCookies(res,newAccessToken,newRefreshToken,newAccessTokenExp,newRefreshTokenExp)

            res.status(200).send({
                status:"success",
                message:"New token generateed",
                access_token:newAccessToken,
                refresh_token:newRefreshToken,
                access_token_exp:newAccessTokenExp,
            });
            
        } catch (error) {
            console.log(error);
            res.status(500).json({status:"failed",message:"Unable to get new access token, please try again later"});
            
        }
    }

    //Profile OR Logged in User
    static userProfile = async (req,res) =>{
        console.log(req.user);
        res.send({"user":req.user});
    }
}

export default UserController;