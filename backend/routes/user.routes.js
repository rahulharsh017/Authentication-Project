import express from 'express';
import UserController from '../controllers.js/user.controller.js';
import passport from 'passport';
import setAuthHeader from '../middleware/setAuthHeader.js';
import accessTokenAutoRefresh from '../middleware/accessTokenAutoRefresh.js';

const router = express.Router();

router.post('/register',UserController.userRegistration);
router.post('/verify-email',UserController.verifyEmail);
router.post('/login',UserController.userLogin);
router.post('/refresh-token',UserController.getNewAccessToken);
router.post('/reset-password-link',UserController.sendUserPassowrdResetEmail);
router.post('/reset-password-link/:id/:token',UserController.userPasswordReset);

//Protected Route
router.get('/me',accessTokenAutoRefresh,passport.authenticate('jwt',{
    session:false
}),UserController.userProfile);

router.post('/change-password',accessTokenAutoRefresh,passport.authenticate('jwt',{
    session:false
}),UserController.changeUserPassword);

router.get('/logout',accessTokenAutoRefresh,passport.authenticate('jwt',{
    session:false
}),UserController.userLogout);

export default router;
