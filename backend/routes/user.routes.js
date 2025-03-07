import express from 'express';
import UserController from '../controllers.js/user.controller.js';

const router = express.Router();

router.post('/register',UserController.userRegistration);
router.post('/verify-email',UserController.verifyEmail);
router.post('/login',UserController.userLogin);

export default router;
