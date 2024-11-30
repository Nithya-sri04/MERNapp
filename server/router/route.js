import {Router} from 'express';
const router = Router();
import * as controller from '../controllers/appController.js';

/** POST METHODS */


router.route('/register').post(controller.register);
//router.route('/registerMail').post(); //sent the email
router.route('/authenticate').post((req,res) => res.end()); // authenticate user
router.route('/login').post(controller.login); // login the app



/**Get methodss */
router.route('/user/username').get(controller.getUser);// user with username
router.route('/generateOTP').get(controller.generateOTP); // generate roandom OTP
router.route('/verifyOTP').get(controller.verifyOTP); // VERIFY OTP
router.route('/createResetSession').get(controller.createResetSession) // resetn all varaibles





/**PUT METHODS */
router.route('/updateUser').put(controller.updateUser);
router.route('/resetPassword').put(controller.resetPassword);


export default router;