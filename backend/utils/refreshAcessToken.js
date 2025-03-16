import UserModel from "../models/user.model.js";
import verifyRefreshToken from "./verifyRefreshToken.js";
import UserRefreshTokenModel from "../models/UserRefreshToken.Model.js";
import generateTokens from "./generateTokens.js";

const refreshAccessToken = async(req,res) =>{
    try {
        const oldRefreshToken = req.cookies.refreshToken;

        const {tokenDetails, error} = await verifyRefreshToken(oldRefreshToken)

        const user = await UserModel.findById(tokenDetails._id)

        const userRefreshToken = await UserRefreshTokenModel.findOne({ userId:tokenDetails._id})

        if(!user){
            return res.status(404).send({status:"failed",message:"User not found"});
        }

        if(oldRefreshToken !== userRefreshToken.token || userRefreshToken.blacklisted){
            return res.status(401).send({status:"failed",message:"Unauthorized access"});
        }
        
        const {accessToken,refreshToken,accessTokenExp,refreshTokenExp} = await generateTokens(user);

        if(error){
            return res.status(401).send({status:"failed",message:"Invalid Refresh Token"});
        }
        
        return{
            newAccessToken:accessToken,
            newRefreshToken:refreshToken,
            newAccessTokenExp:accessTokenExp,
            newRefreshTokenExp:refreshTokenExp
        }
    } catch (error) {
        console.log(error);
        res.status(500).send({status:"failed",message:"Internal Server Error"});
        
    }
}

export default refreshAccessToken;