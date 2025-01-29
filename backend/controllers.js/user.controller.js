import UserModel from "../models/user.model.js";
import bcrypt from "bcrypt";
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

             return res.status(201).json(
                {status:"success",
                    message:"User Registered Successfully",
                user:{id:newUser._id,name:newUser.name,email:newUser.email}});
            
        } catch (error) {
            console.log(error);
            res.status(500).json({status:"failed",message:"Unable to Resgister, please try again later"});
            
        }
    }
}

export default UserController;