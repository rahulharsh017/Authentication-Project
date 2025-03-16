import express from 'express';
import UserController from '../controllers.js/user.controller.js';
import passport from 'passport';

const router = express.Router();

router.post('/register',UserController.userRegistration);
router.post('/verify-email',UserController.verifyEmail);
router.post('/login',UserController.userLogin);
router.post('/refresh-token',UserController.getNewAccessToken);

//Protected Route
router.get('/me',passport.authenticate('jwt',{
    session:false
}),UserController.userProfile);

export default router;
