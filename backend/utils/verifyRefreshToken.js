import jwt from 'jsonwebtoken';
import UserRefreshTokenModel from '../models/UserRefreshToken.Model.js';

const verifyRefreshToken = async (refreshToken) =>{
try {
    const privateKey = process.env.JWT_REFRESH_TOKEN_SECRET_KEY;

    const userRefreshToken = await UserRefreshTokenModel.findOne({token: refreshToken})

    if(!userRefreshToken){
        throw {error: true, message: "Invalid Refresh Token"};
    }

    const tokenDetails = jwt.verify(refreshToken,privateKey);

    return{
        tokenDetails,
        error:false,
        message:"Valid Refresh Token"
    }
} catch (error) {

    throw {error:true,message:"Invalid Refresh Token"};
    
}
}

export default verifyRefreshToken;