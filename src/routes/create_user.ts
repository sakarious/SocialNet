import express from "express";
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs";
import { Users } from "../entities/Users";

const router = express.Router();

let authenticateUser = (req: express.Request, res: express.Response, next: express.NextFunction):any => {
    if(!req.headers.authorization){
        return res.status(401).json({error: true, message: "Authorization header required"})
    }

    jwt.verify(req.headers.authorization, String(process.env.secret), (err?: any, decodeToken?: any): any => {
        if(err){
            return res.status(500).json({error: true, message: "oppsss... Somethiing went wrong"})
        }

        if(!decodeToken){
            return res.status(401).json({error: true, message: "Invalid Authorization token, Please login"})
        }

        req.body.id = decodeToken.id
        next()
    })
}


router.get('/api/v1/user', (req,res) => {
    res.send("Welcome to Users")
});

router.post('/api/v1/signup', async (req,res): Promise<any> => {
    try {
        
            //Condition 1:  Check the signup request body for missing fields or incorrect fields.
            if(req.body.hasOwnProperty('fullname') && req.body.hasOwnProperty('email') && req.body.hasOwnProperty('password') && req.body.hasOwnProperty('confirmPassword')){
                //All required Fields are given. Now Validate Email address given
                if(req.body.email.match(/.+\@.+\..+/)){
                    //Email Given is valid, now see if password and confirm password matches
                    if(req.body.password === req.body.confirmPassword){
                        //Password Matches now test if password is strong
                        if(req.body.password.match(/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})/)){
                            //Password is strong now stop multiple users frim registering with same email
                            let usersWithSameEmail = await Users.findOne({email: req.body.email})
                            if(usersWithSameEmail){
                                return res.json({
                                    error: true,
                                    message: "Email Taken Please Login or try another email address"
                                })
                            } else {
                                //Email is not taken. Encrypt User's Password
                                let hash = bcrypt.hashSync(req.body.password, 10);
                                //If password has been hashed, create user
                                let newUser;
                                if(hash){ 
                                        newUser = Users.create({
                                            fullname: req.body.fullname,
                                            password: hash,
                                            email: req.body.email,
                                        })
                                        await newUser.save()

                                        //After Creating User, Generate jwt for user
                                        if(newUser){
                                            //Generate Token
                                            const payload = {id: newUser.id}
                                            const secret = String(process.env.secret)
                                            const expiry = "24h"

                                            let token = await jwt.sign(payload, secret, { expiresIn: expiry})

                                            if (token){
                                                return res.json({
                                                    error: false,
                                                    message: "Account Created Successfully",
                                                    token
                                                })
                                            } else {
                                                return res.status(500).json({
                                                    error: true,
                                                    message: "Oppsss. Something went wrong while Creating Token"
                                                })
                                            }

                                        } else {
                                            return res.status(500).json({
                                                error: true,
                                                message: "Oppsss. Something went wrong while Creating User"
                                            })
                                        }

                                    } else {
                                        return res.status(500).json({
                                            error: true,
                                            message: "Oppsss. Something went wrong #"
                                        })
                                    }
                                }
                                

                        } else{
                            return res.json({
                                error: true,
                                message: "Password not strong. A strong password consists of at least six characters (and the more characters, the stronger the password) that are a combination of letters, numbers and symbols (@, #, $, %, etc.) if allowed. Passwords are typically case-sensitive, so a strong password contains letters in both uppercase and lowercase."
                            })
                        }

                    } else{
                        return res.json({
                            error: true,
                            message: "Password and Confirm password do not match"
                        })
                    }

                } else {
                    return res.json({
                        error: true,
                        message: "Email is Invalid"
                    })
                }

            } else {
                return res.json({
                    error: true,
                    message: "Fullname, Email, Password and Confirm Password Fields are required"
                })
            }
        } catch (error) {
            console.log(error)
            return res.status(500).json({
                error: true,
                message: "Internal Server Error"
            })
        }
});

router.post('/api/v1/login', async (req,res): Promise<any> => {
    /**
     * Login

        1. Return the correct error if a user enters the wrong information "User does not exist" or "Wrong password".

        2. Return a timed JWT to allow a user to access locked routes.

        3. *bonus* If a user tries to log in more than 5 times and fails, block them from trying for an hour.
     */
    try {
        
            //Condition 1:  Check the signup request body for missing fields or incorrect fields.
            if(req.body.hasOwnProperty('email') && req.body.hasOwnProperty('password')){
                //All required Fields are given. Now Validate Email address given
                let userEmail = await Users.findOne({email: req.body.email})
                if(userEmail){
                    //User Exists. Now Validate Password
                    let match = bcrypt.compareSync(req.body.password, userEmail.password)
                    if (match){
                        //return res.json(userEmail)
                        //Password matches and locktime is 0, Return timed JWT and update login count to 0 and timer to 0
                        if(Number(userEmail.lockTime) == 0){
                            //Generate Token
                            const payload = {id: userEmail.id}
                            const secret = String(process.env.secret)
                            const expiry = "24h"

                            let token = await jwt.sign(payload, secret, { expiresIn: expiry})

                            if (token){
                                return res.json({
                                    error: false,
                                    message: "Login Success",
                                    token
                                })
                            } else {
                                return res.status(500).json({
                                    error: true,
                                    message: "Oppsss. Something went wrong while Creating Token"
                                })
                            }

                        } else {
                            //else if password matches and locktime is greated than current time tell user to wait else Return timed JWT and update login count to 0 and timer to 0
                            let currentTimeStamp = new Date().getTime()
                            if(currentTimeStamp > Number(userEmail.lockTime)){
                                //Generate token
                                const payload = {id: userEmail.id}
                                const secret = String(process.env.secret)
                                const expiry = "24h"

                                let token = await jwt.sign(payload, secret, { expiresIn: expiry})

                                if (token){
                                    userEmail.lockTime = '0'
                                    userEmail.loginCount = 0
                                    await userEmail.save()

                                    return res.json({
                                        error: false,
                                        message: "Login Success",
                                        token
                                    })

                                    
                                } else {
                                    return res.status(500).json({
                                        error: true,
                                        message: "Oppsss. Something went wrong while Creating Token"
                                    })
                                }
                            } else {
                                return res.status(500).json({
                                    error: true,
                                    message: "Your Account is currently locked."
                                })
                            }

                        }

                    } else {
                        //Wrong Password, Check user login time
                        if(userEmail.loginCount >= 5){
                            //Update Locktime with current time + 1 hour and inform user about account lock
                            //Get current timestamp
                            let tp = new Date(); //Current time
                            tp.setHours( tp.getHours() + 1 ); //Add one hour to current time
                            let oneHour = (tp.getTime()) //Next one hour timestamp

                            userEmail.lockTime = String(oneHour)
                            await userEmail.save()

                            return res.json({
                                error: true,
                                message: "Incorrect Password. You account has been locked please try again in one hour"
                            })

                        } else {
                            //Update userLogin count.
                            userEmail.loginCount = userEmail.loginCount + 1
                            await userEmail.save()

                            return res.json({
                                error: true,
                                message: "Incorrect Password"
                            })
                        }

                    }
                    //return res.json(userEmail)
                } else {
                    return res.json({
                        error: true,
                        message: "User Does not Exist"
                    })
                }

            } else {
                return res.json({
                    error: true,
                    message: "Email and Password Fields are required"
                })
            }
        } catch (error) {
            console.log(error)
            return res.status(500).json({
                error: true,
                message: "Internal Server Error"
            })
        }
});

router.post('/api/v1/getUser', authenticateUser, async (req,res): Promise<any> => {
    /**
     * Get User

    1. Only logged in users can access this route

    2. Return the logged-in user details.

     */
    try {
        //Find User
        let user= await Users.findOne({id: req.body.id})
        if (user) {
            return res.json({
                error: false,
                userDetails: {
                    "Fullname": user.fullname,
                    "Email": user.email
                }
            })

        } else {
            return res.json({
                error: true,
                message: "User Does not Exist"
            })
        }

        
    } catch (error) {
        console.log(error)
        return res.status(500).json({
            error: true,
            message: "Internal Server Error"
        })
    }
    
    
});

export {
    router as createUserRouter
}