import isTokenExpire from "../utils/isTokenExpired.js";
import refreshAccessToken from "../utils/refreshAcessToken.js";
import setTokenCookies from "../utils/setTokenCookies.js";

const accessTokenAutoRefresh = async (req, res, next) => {
    try {
        const accessToken = req.cookies.accessToken;

        if(accessToken || !isTokenExpire(accessToken)){
            req.headers['authorization'] = `Bearer ${accessToken}`;
        }
        if(!accessToken || isTokenExpire(accessToken)){
            const refreshToken = req.cookies.refreshToken;
            if(!refreshToken){
                throw new Error('No refresh token found');
            }
            const {newAccessToken,newRefreshToken,newAccessTokenExp,newRefreshTokenExp} = await refreshAccessToken(req,res);

            setTokenCookies(res,newAccessToken,newRefreshToken,newAccessTokenExp,newRefreshTokenExp);

            req.headers['authorization'] = `Bearer ${accessToken}`;
        }

        next();
        
    } catch (error) {
        console.error('Error adding access token to header',error.message);

        res.status(401).json({error:'Unauthorized',message:'Access token is missing or invalid'})
        
    }
}

export default accessTokenAutoRefresh;