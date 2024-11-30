import UserModel from '../model/User.model.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import ENV from '../config.js'
import otpGenerator from 'otp-generator';

/** middleware for verify user */
export async function verifyUser(req, res, next) {
    try {
        const { username } = req.method === "GET" ? req.query : req.body;

        // Check if the user exists in the database
        const user = await UserModel.findOne({ username });

        if (!user) {
            // Respond with 404 if user doesn't exist
            return res.status(404).send({ error: "User not found!" });
        }

        // Proceed to the next middleware if the user exists
        next();

    } catch (error) {
        // Respond with 500 for unexpected errors (server-side)
        console.error("Error verifying user:", error);
        return res.status(500).send({ error: "Failed to verify user, please try again later." });
    }
}



/** POST: http://localhost:8080/api/register 
 * @param : {
  "username" : "example123",
  "password" : "admin123",
  "email": "example@gmail.com",
  "firstName" : "bill",
  "lastName": "william",
  "mobile": 8009860560,
  "address" : "Apt. 556, Kulas Light, Gwenborough",
  "profile": ""
}
*/
export async function register(req, res) {
    try {
        const { username, password, profile, email } = req.body;
        
        if (!username || !password || !email) {
            return res.status(400).send({ error: "Username, password, and email are required" });
        }

        // Check if username already exists
        const existingUsername = await UserModel.findOne({ username });
        if (existingUsername) {
            return res.status(400).send({ error: "Please use a unique username" });
        }

        // Check if email already exists
        const existingEmail = await UserModel.findOne({ email });
        if (existingEmail) {
            return res.status(400).send({ error: "Please use a unique email" });
        }

        // Hash the password
        if (!password) {
            return res.status(400).send({ error: "Password is required" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Create and save the user
        const user = new UserModel({
            username,
            password: hashedPassword,
            profile: profile || '', // Default to an empty string if no profile provided
            email,
        });

        await user.save();

        return res.status(201).send({ msg: "User registered successfully" });
    } catch (error) {
        console.error("Error in /api/register:", error.message);
        return res.status(500).send({ error: "Internal Server Error" });
    }
}



/** POST: http://localhost:8080/api/login 
 * @param: {
  "username" : "example123",
  "password" : "admin123"
}
*/
export async function login(req, res) {
    const { username, password } = req.body;

    try {
        // Check if user exists
        const user = await UserModel.findOne({ username });
        if (!user) {
            return res.status(404).send({ error: "Username not found" });
        }

        // Compare passwords
        const passwordCheck = await bcrypt.compare(password, user.password);
        if (!passwordCheck) {
            return res.status(400).send({ error: "Password doesn't match" });
        }

        // Create JWT token
        const token = jwt.sign({
            userId: user._id,
            username: user.username
        }, ENV.JWT_SECRET, { expiresIn: "24h" });

        return res.status(200).send({
            msg: "Login Successful",
            username: user.username,
            token
        });
    } catch (error) {
        console.error("Error during login:", error.message);
        return res.status(500).send({ error: "Internal Server Error" });
    }
}

/** GET: http://localhost:8080/api/user/example123 */
export async function getUser(req, res) {
  const { username } = req.params;

  // Ensure username is provided
  if (!username) {
    return res.status(400).send({ error: "Invalid Username" }); 
  }

  try {
    
    const user = await UserModel.findOne({ username });
    if (!user) {
      return res.status(404).send({ error: "Couldn't Find the User" }); 
    }
    const { password, ...rest } = user.toObject();

    return res.status(200).send(rest); 
  } catch (error) {
    console.error("Error fetching user:", error); 
    return res.status(500).send({ error: "Error fetching user data" }); 
  }
}




/** PUT: http://localhost:8080/api/updateuser 
 * @param: {
  "header" : "<token>"
}
body: {
    firstName: '',
    address : '',
    profile : ''
}
*/
export async function updateUser(req,res){
    try {
        
        // const id = req.query.id;
        const { userId } = req.user;

        if(userId){
            const body = req.body;

            // update the data
            UserModel.updateOne({ _id : userId }, body, function(err, data){
                if(err) throw err;

                return res.status(201).send({ msg : "Record Updated...!"});
            })

        }else{
            return res.status(401).send({ error : "User Not Found...!"});
        }

    } catch (error) {
        return res.status(401).send({ error });
    }
}


/** GET: http://localhost:8080/api/generateOTP */
export async function generateOTP(req,res){
    req.app.locals.OTP = await otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false})
    res.status(201).send({ code: req.app.locals.OTP })
}


/** GET: http://localhost:8080/api/verifyOTP */
export async function verifyOTP(req,res){
    const { code } = req.query;
    if(parseInt(req.app.locals.OTP) === parseInt(code)){
        req.app.locals.OTP = null; // reset the OTP value
        req.app.locals.resetSession = true; // start session for reset password
        return res.status(201).send({ msg: 'Verify Successsfully!'})
    }
    return res.status(400).send({ error: "Invalid OTP"});
}


// successfully redirect user when OTP is valid
/** GET: http://localhost:8080/api/createResetSession */
export async function createResetSession(req,res){
   if(req.app.locals.resetSession){
        return res.status(201).send({ flag : req.app.locals.resetSession})
   }
   return res.status(440).send({error : "Session expired!"})
}


// update the password when we have valid session
/** PUT: http://localhost:8080/api/resetPassword */
export async function resetPassword(req,res){
    try {
        
        if(!req.app.locals.resetSession) return res.status(440).send({error : "Session expired!"});

        const { username, password } = req.body;

        try {
            
            UserModel.findOne({ username})
                .then(user => {
                    bcrypt.hash(password, 10)
                        .then(hashedPassword => {
                            UserModel.updateOne({ username : user.username },
                            { password: hashedPassword}, function(err, data){
                                if(err) throw err;
                                req.app.locals.resetSession = false; // reset session
                                return res.status(201).send({ msg : "Record Updated...!"})
                            });
                        })
                        .catch( e => {
                            return res.status(500).send({
                                error : "Enable to hashed password"
                            })
                        })
                })
                .catch(error => {
                    return res.status(404).send({ error : "Username not Found"});
                })

        } catch (error) {
            return res.status(500).send({ error })
        }

    } catch (error) {
        return res.status(401).send({ error })
    }
}

