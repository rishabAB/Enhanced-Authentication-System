const mysql = require('mysql2');

const express = require('express')

const jwt = require('jsonwebtoken');

require('dotenv').config();

const SECRET_KEY=process.env.SECRET_KEY;

const app = express();

app.use(express.json({ limit: '50mb' }));


const bodyParser = require('body-parser');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const cors = require("cors");
const bcrypt=require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const { rateLimit } =require('express-rate-limit');
const mailer = require('nodemailer');

const limiter = rateLimit({
	windowMs: 1 * 60 * 1000, // 1 minute
	limit: 20, // for each minute we could receive 20 requests
	standardHeaders: 'draft-7',
	legacyHeaders: false, 
	message: "Too many requests please try again later"
});
app.use(limiter);

app.listen(7000, () => {
    console.log("server is up to 7000")
})

// ----Mysql connection---------

const connection = mysql.createConnection({
     host: "localhost", 
     user: "root", 
     password: "password",
      database: "auth",
       port: "3306"
     })

connection.connect(function (err) {
    if (err) {
        console.log("error occurred while connecting");
        console.log(err);
    }
    else {
        console.log("connection created with Mysql successfully");
    }
});

// FUNCTIONS FOR CREATING ACCOUNT
const validateAccountCreation = (req, res, next) => {
    
    const { name, email, password, account_type,phone_number,photo } = req.body;
    const validAccountTypes = ['public', 'private'];

    // Check if required fields are present
    if (!name || !email || !password || !account_type || !phone_number) {
        return res.status(400).json({ error: 'Missing required fields name ,email ,password, account_type and phone_number are required' });
    }
   
    if (!validAccountTypes.includes(account_type)) {
        return res.status(400).json({ error: 'Invalid account type' });
    }

    if (!/\S+@\S+\.\S+/.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!/^(\+91)?\d{10}$/.test(phone_number)) {
        return res.status(400).json({ error: 'Invalid phone number format' });
    }

    // Validate password requirements (1 special character, 1 capital letter, minimum 8 characters)
    if (!/(?=.*\d)(?=.*[A-Z])(?=.*\W).{8,}/.test(password)) {
        return res.status(400).json({ error: 'Password must contain at least one special character, one capital letter, and should be atleast 8 characters long' });
    }

    // If all validations pass, call next to proceed
    next();
};


function getTableDataById(id) {
    return new Promise((resolve, reject) => {
        // Check account_type for the given id
        const checkAccountTypeSql = `SELECT account_type FROM user_accounts WHERE id = ?`;
        connection.query(checkAccountTypeSql, [id], (error, results) => {
            if (error) {
            reject(error);
            } else {
            if (results.length === 0) {
                // No record found for the given id
                resolve([]);
            } else {
                const accountType = results[0].account_type;
                let query;
    
                if (accountType === 'public' || accountType === "private") {
                // If account_type is public, fetch data where account_type is public or public
                query = `SELECT name,bio,photo FROM user_accounts WHERE account_type = 'public' AND id!='${id}'`;
                } else {
                // If account_type is private, fetch data where account_type is public or private
                query = `SELECT name,bio,photo FROM user_accounts WHERE account_type IN ('public', 'private') AND id!='${id}'`;
                }
    
                // Execute the final query
                connection.query(query, (error, results) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(results);
                }
                });
            }

            }
        });
    });
  }




function createAccountInDb(name, email, password, account_type, phone_number, photo, bio) {
    return new Promise((resolve, reject) => {
        // Generate UUID
        const id = uuidv4();

        // Check if email or phone number already exists
        connection.query(
            `SELECT * FROM user_accounts WHERE email = ? OR phone_number = ?`,
            [email, phone_number],
            (error, results) => {
                    if (error) {
                        console.error('Error checking for existing email/phone:', error);
                        reject(error);
                    } else if (results.length > 0) {
                        // Email or phone number already exists
                        const existingField = results[0].email === email ? 'email' : 'phone number';
                        const errorMessage = `Account creation failed: ${existingField} already exists`;
                        resolve({ isActionSuccess: false, message: errorMessage });
                    } else {
                        // Proceed with insertion
                        const sql = `
                            INSERT INTO user_accounts (id, name, email, password, account_type, phone_number, photo, bio)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        `;
                        const values = [id, name, email, password, account_type, phone_number, photo, bio];
                        
                        connection.query(sql, values, (insertionError, insertionResults) => {
                            if (insertionError) {
                                console.error('Error creating account:', insertionError);
                                reject(insertionError);
                            } else {
                                console.log('Account created successfully:', insertionResults);
                                resolve({ isActionSuccess: true, insertedId: id });
                            }
                        });
                    }
            }
        );
    });
}



// REGISTER ROUTE FOR PUBLIC OR PRIVATE ACCOUNT
app.post("/createAccount", validateAccountCreation,async (req, res) => {

const { name, email, password, account_type,phone_number,photo,bio } = req.body;

    // storing password in hashed form
    bcrypt.hash(password, 10).then(async (hash) => {
        createAccountInDb(name,email,hash,account_type,phone_number,photo,bio)
            .then((result) => {
                if(result.isActionSuccess)
                {
                    const maxAge = 60 * 5; 
                    const token = jwt.sign(
                    { id: result.insertedId},
                    SECRET_KEY,
                    {
                        expiresIn: maxAge, // 5min in sec
                    }
                    );
                
                    res.status(201).json({
                    isActionSuccess:true,
                    id:result.insertedId,
                    message: "User successfully created",
                    token:token
                    });

                }
                else{
                    res.status(400).json({
                        isActionSuccess:false,
                        error:result.error,
                        message:result.message
                    })
                }
            
            })
            .catch((error) =>
                res.status(400).json({
                message: "User not successfully created",
                error: error.message,
                })
            );

    })

});



// LOGOUT FUNCTIONS AND ROUTE 

async function logoutUser(id) {
    return new Promise((resolve, reject) => {
        // Check if the id exists in the database
        const checkIdSql = `SELECT * FROM user_accounts WHERE id = ?`;
        connection.query(checkIdSql, [id], (error, results) => {
            if (error) {
            reject(error);
            } else {
            if (results.length === 0) {
                // No record found for the provided id
                resolve({isActionSuccess:false,message:"This user does not exist"});
            } else {
                // Update the isUserLoggedIn column to false for the provided id
                const updateSql = `UPDATE user_accounts SET isUserLoggedIn = FALSE WHERE id = ?`;
                connection.query(updateSql, [id], (error) => {
                if (error) {
                    reject(error);
                } else {
                    resolve({isActionSuccess:true});
                }
                });
            }
            }
        });
    });
  }


app.get("/logout",(req,res)=>
{
    const {id}= req.body;
    if(id && id.length > 0)
    {
        logoutUser(id).then(function(result)
        {
            if(result.isActionSuccess)
            {
                res.status(200).json({message:"You have successfully logged out"});
            }
            else{
                res.status(200).json({message:result.message});
            }
        })

    }
    else{
        res.status(400).json({message:"Invalid parameters passed"});
    }
}) 


// LOGIN FUNCTIONS AND ROUTE

async function getUserByUsername(email) {
    return new Promise((resolve, reject) => {
            // SQL query to retrieve user data by email
            const sql = `SELECT * FROM user_accounts WHERE email = ?`;

            // Execute the query
            connection.query(sql, [email], (error, results) => {
                if (error) {
                    console.error('Error retrieving user by email:', error);
                    reject(error);
                } else {
                    // If user found, set isLoggedIn to true
                    if (results.length > 0) {
                        const user = results[0];
                        const emailId = user.email;
                        // Update the user's isLoggedIn status to true
                        updateUserLoginStatus(emailId)
                            .then(() => {
                                // Set isLoggedIn to true before resolving
                                user.isUserLoggedIn = true;
                                resolve(user);
                            })
                            .catch(updateError => {
                                console.error('Error updating user isLoggedIn status:', updateError);
                                reject(updateError);
                            });
                    } else {
                        // If user not found, resolve with null
                        resolve(null);
                    }
                }
            });
    });
}

// Function to update the user's login status
function updateUserLoginStatus(emailId) {
    return new Promise((resolve, reject) => {
        // SQL query to update the isLoggedIn status
        const sql = `UPDATE user_accounts SET isUserLoggedIn = true WHERE email = ?`;

        connection.query(sql, [emailId], (error, results) => {
            if (error) {
                reject(error);
            } else {
                resolve();
            }
        });
    });
}


function validateRequestBody(req, res, next) {
    const { email, password } = req.body;

    // Check if username is missing
    if (!email) {
        return res.status(400).json({ error: 'Please provide your email address' });
    }
    
    // Check if password is missing
    if (!password) {
        return res.status(400).json({ error: 'Please provide your password' });
    }

    // If both username and password are present, proceed to the next middleware
    next();
}

app.post('/login', validateRequestBody,async (req, res) => {
    const { email, password } = req.body;

    try {
        // Retrieve user data from the database based on the username
        const userData = await getUserByUsername(email);

        // If no user found with the given username
        if (!userData) {
            return res.json({ isActionSuccess: false, message: 'This user does not exist' });
        }

        // Compare the hashed password with the provided password
        const passwordMatch = await bcrypt.compare(password, userData.password);

        // If passwords match, return user data
        if (passwordMatch) {
            const { name, username, phone_number, account_type, photo,bio,id } = userData;

            let data =await getTableDataById(id);
          

            // --- create and return jwt token---
          
            const maxAge = 60 * 5; 
            const token = jwt.sign(
              { id:id },
              SECRET_KEY,
              {
                expiresIn: maxAge, // 5 min in sec
              }
            );

            return res.json({
                isActionSuccess: true,
                myProfile: { name, phone_number, email,account_type, photo,bio },
                otherPublicUsers:data,
                token : token
            });
        } else {
            // Passwords don't match
            return res.json({ isActionSuccess: false, message: 'Username or password is incorrect' });
        }
    } catch (error) {
        console.error('An unknown error during login:', error);
        return res.status(500).json({ isActionSuccess: false, message: 'Internal server error' });
    }
});


//EDIT PROFILE ROUTES AND FUNCTIONS

async function checkIfUserIsLoggedIn(id) {
    return new Promise((resolve, reject) => {
        // SQL query to check if the user is logged in based on email
        const sql = 'SELECT isUserLoggedIn FROM user_accounts WHERE id = ?';

        connection.query(sql, [id], (error, results) => {
            if (error) {
                console.error('Error checking if user is logged in:', error);
                reject(error);
            } else {
                // If user found, return true if isUserLoggedIn is true, otherwise false
                if (results.length > 0) {
                    resolve(results[0].isUserLoggedIn === 1);
                } else {
                    // If user not found, resolve with false
                    resolve(false);
                }
            }
        });
    });
}

async function isAuthenticatedByGoogle(id)
{
    return new Promise((resolve, reject) => {
        // SQL query to check if the user is googleauthenticated on the basisi of email
        const sql = 'SELECT isGoogleAuthenticated FROM user_accounts WHERE id = ?';

        // Execute the query
        connection.query(sql, [id], (error, results) => {
            if (error) {
                console.error('Error checking if user is logged in:', error);
                reject(error);
            } else {
                // If user found, return true if isUserLoggedIn is true, otherwise false
                if (results.length > 0) {
                    resolve(results[0].isGoogleAuthenticated === 1);
                } else {
                    // If user not found, resolve with false
                    resolve(false);
                }
            }
        });
    });

}

async function authenticateToken(req, res, next) {
    // Get the JWT token from the request headers
    const token = req.headers['authorization'];

    if(req.body && req.body.id== undefined )
    {
        return res.status(400).json({message:'Please provide the id to update your user details'});
    }
    if(req.body.id.length == 0)
    {
       return res.status(400).json({message:'Please provide the id to update your user details'});
    }

    if(await isAuthenticatedByGoogle(req.body.id))
    {
        next();
    }
    else{
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized: Missing token' });
        }
    
        // Verify the JWT token
        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err || decoded.id !== req.body.id) {
                return res.status(403).json({ error: 'Forbidden: Invalid Access token' });
            }
           
            req.user = decoded; // Attach the decoded user information to the request object
            next();
        });

    }

   
}

function CreateUpdateObjectAndQuery(id,name, email, phone_number, photo, bio,account_type) {
    return new Promise((resolve, reject) => {
        // Construct the SQL UPDATE query
        let updateQuery = 'UPDATE user_accounts SET';
        let updateValues = [];

        // Append fields to updateQuery if they are provided
        if (name) {
            updateQuery += ' name = ?,';
            updateValues.push(name);
        }
        if (phone_number) {
            updateQuery += ' phone_number = ?,';
            updateValues.push(phone);
        }
        if (photo) {
            updateQuery += ' photo = ?,';
            updateValues.push(photo);
        }
        if (bio) {
            updateQuery += ' bio = ?,';
            updateValues.push(bio);
        }
        if (email) {
            updateQuery += ' email = ?,';
            updateValues.push(email);
        }
        if(account_type)
        {
            updateQuery += ' account_type = ?,';
            updateValues.push(account_type);
        }

        // Remove the trailing comma
        updateQuery = updateQuery.slice(0, -1);

        // Append the WHERE clause to update only the specified user's row
        updateQuery += ' WHERE id = ?';
        updateValues.push(id);
        
        // Resolve the promise with the constructed query and values
        resolve({ query: updateQuery, updateValues: updateValues });
    });
}

function validateUpdateParameters(name, email, phone_number, photo, bio,account_type) {
    return new Promise((resolve, reject) => {
        
      
        if(account_type)
        {
            const validAccountTypes = ['public', 'private'];
            if (!validAccountTypes.includes(account_type)) {
                return res.status(400).json({ error: 'Invalid account type' });
            }
        }

        // Validate email format
        if(email)
        {
            if (!/\S+@\S+\.\S+/.test(email)) {
                return res.status(400).json({ error: 'Invalid email format' });
            }

        }
        if(phone_number)
        {
            if (!/^(\+91)?\d{10}$/.test(phone_number)) {
                return res.status(400).json({ error: 'Invalid phone number format' });
            }

        }

        if (!name && !email && !phone_number && !photo && !bio) {
            // If none of the parameters are provided, reject the promise with an error message
            resolve({isValid:false,message:'Please provide at least one parameter to update'});
        } else {
            // At least one parameter is provided, so resolve the promise with a valid flag
            resolve({ isValid: true });
        }
    });
}


app.put('/editProfile', authenticateToken,async (req, res) => {
    let returnObject={message:null};
    const { id,name, email, phone_number, photo, bio,account_type } = req.body;
 
        checkIfUserIsLoggedIn(id)
        .then((isLoggedIn) => {
            if (!isLoggedIn) {
                returnObject.message= "Please log in into your account in order to edit your profile";
              
            }
            else{
            return validateUpdateParameters(name, email, phone_number, photo, bio,account_type);

            }
           
        })
        .then((validationResult) => {
            if (validationResult && !validationResult.isValid) {
                returnObject.message=validationResult.message
            }
            else{
                // If update parameters are valid, create update object and query
            return CreateUpdateObjectAndQuery(id,name, email, phone_number, photo, bio,account_type);

            }
            return;
            
        })
        .then((result) => {
            // Execute the UPDATE query
            if(returnObject.message == undefined && result!=undefined)
            {
                return new Promise((resolve, reject) => {
                    connection.query(result.query, result.updateValues, (error, results) => {
                        if (error) {
                            console.error('Error updating user:', error);
                            reject(error);
                        } else {
                            resolve();
                        }
                    });
                });

            }
            return;
           
        })
        .then(() => {
            // If update is successful, send success response
            if(returnObject.message)
            {
                res.json({isActionSuccess:false,errorMessage:returnObject.message});
            }
            else{
                res.json({ isActionSuccess: true, message: 'User updated successfully' });

            }
          
        })
        .catch((error) => {
            // If any error occurs, send error response
            console.error('Error updating user:', error);
            res.status(500).json({ error: 'Internal server error' });
        });

   
});


// SIGN IN WITH GOOGLE FUNCTIONS AND ROUTES
// NOTE FOR SIGINING IN WITH GOOGLE YOU CANNOT HIT A ROUTE 
// THERE MUST ME A UI SO GO TO localhost 7000 IN ORDER TO SIGN IN WITH GOOGLE
async function saveGoogleAccountDataInDb(email, name, photo) {
    return new Promise((resolve, reject) => {
        // Check if the email already exists in the database
        connection.query(
            'SELECT * FROM user_accounts WHERE email = ?',
            [email],
            (error, results) => {
                if (error) {
                    console.error('Error checking for existing email:', error);
                    reject(error);
                } else if (results.length > 0) {
                    // If email already exists, return a promise indicating failure
                    resolve({ isActionSuccess: false, message: 'This email already exists' });
                } else {
                    // Email doesn't exist, proceed with insertion
                    const id = uuidv4(); // Generate UUID for the user
                    const isGoogleAuthenticated = true;
                    const isUserLoggedIn = true;

                    // Insert the data into the user_accounts table
                    connection.query(
                        'INSERT INTO user_accounts (id, name, email, photo, isGoogleAuthenticated,isUserLoggedIn) VALUES (?, ?, ?, ?, ?, ?)',
                        [id, name, email, photo, isGoogleAuthenticated,isGoogleAuthenticated],
                        (insertError, insertResults) => {
                            if (insertError) {
                                console.error('Error inserting user account data:', insertError);
                                reject(insertError);
                            } else {
                                // Return a promise indicating success
                                resolve({ isActionSuccess: true,id:id });
                            }
                        }
                    );
                }
            }
        );
    });
}
const session=require("express-session");

const passport=require("passport");
require("./passport");

app.use(session({
    resave:false,
saveUninitialized:true,
secret:process.env.SESSION_SECRET
}));


app.use(passport.initialize());
app.use(passport.session());



app.get('/', (req,res) =>
{
    res.render('auth');
});

app.set('view engine', 'ejs');

app.get('/auth/google' , passport.authenticate('google', { scope: 
	[ 'email', 'profile' ] 
})); 

// Auth Callback 
app.get('/auth/google/callback', 
	passport.authenticate( 'google', { 
		successRedirect: '/success', 
		failureRedirect: '/failure'
}));

// Success 
app.get('/success' , (req,res)=>
{
    if(!req.user)
    res.redirect('failure');
    
    if(req.user && req.user._json)
    {
        const email=req.user._json.email;
        const name=req.user._json.name;
        const photo=req.user._json.picture;

        saveGoogleAccountDataInDb(email,name,photo).then(function(result)
        {
            if(result.isActionSuccess)
            {
                res.send(`You have successfully registered your account from google with email id ${email} and your id is ${result.id}` );
            }
            else{
                res.send(result.message);
            }
        })


    }
    else{
       
        res.status(400).json({ error: 'Incomplete paramters received from google' });

    }
  
    
}); 

// Failure 
app.get('/failure' , (req,res) =>
{
   
    res.send(500).json({ error: 'Internal server error' });
});



// ADMIN USER FUNCTIONS ANS ITS ROUTES FOR AUTHENTICATION---------------------------


function saveEmailDataInDb(email, otp) {
    return new Promise((resolve, reject) => {
      // Check if the email already exists and isMatched column is true
      const checkEmailSql = `SELECT * FROM admin_User_Verification WHERE email = ?`;
      connection.query(checkEmailSql, [email], (error, results) => {
        if (error) {
          reject(error);
        } else {
          if (results.length === 0) {
            // Email does not exist, insert new data
            const expiryTimestamp = new Date();
            expiryTimestamp.setMinutes(expiryTimestamp.getMinutes() + 5);
            const insertSql = `INSERT INTO admin_User_Verification (email, otp, expiryTimestamp) VALUES (?, ?, ?)`;
            const values = [email, otp, expiryTimestamp];
            connection.query(insertSql, values, (error, results) => {
              if (error) {
                reject(error);
              } else {
                resolve({ isActionSuccess: true });
              }
            });
          } else {
            const userVerificationData = results[0];
            if (userVerificationData.isMatched) {
              // If isMatched is true, account is already authenticated
              resolve({ isActionSuccess:false,message: 'Your account is already authenticated' });
            } else {
              // If isMatched is false, OTP has already been sent
              const currentTime = new Date();
              const expiryTime = new Date(userVerificationData.expiryTimestamp);
              if (currentTime < expiryTime) {
                // If OTP has not expired
                resolve({ isActionSuccess:false,message: 'We have already sent an OTP on this registered email' });
              } else {
                // If OTP has expired
                resolve({isActionSuccess:false,message:'You have already tried with this email for authentication. So for security reasons you cannot register yourself as an admin user with this email'});
              }
            }
          }
        }
      });
    });
  }


  function generateOTP() {
    // Generate a random number between 1000 and 9999 (inclusive)
    const otp = Math.floor(Math.random() * 9000) + 1000;
    return otp;
  }

function sendMailAndSaveDataInDb(email)
{
    return new Promise(async(resolve,reject) =>
    {
        try{
                const otp= generateOTP();
                saveEmailDataInDb(email,otp).then(async function(result)
                {
                    if(result.isActionSuccess)
                    {
                        const transporter = mailer.createTransport({
                            service: 'gmail',
                            auth: {
                                user: 'rishabmehta12480@gmail.com',
                                pass: process.env.NODE_MAILER_PASS
                            }
                        });
            
                        
                    
                        const sendEmail = await transporter.sendMail({
                            // from: 'rishabmehta766@gmail.com',
                            to: email,
                            subject: 'Confirmation mail',
                            html: `<p style="font-size: 1.2em;">Your one time password for your account verification is <strong>${otp}</strong></p>`
                        });

                        if(sendEmail && sendEmail.accepted && sendEmail.accepted.length >0)
                        {
                            resolve({isActionSuccess:true,message:"Email sent successfully"})

                        }
                        else{
                            resolve({isActionSuccess:false,message:"An unknown error occurred while sending email"});
                        }
                    }
                    else{
                        resolve({isActionSuccess:false,message:result.message});
                    }
                })
        }
        catch(ex)
        {
            reject(ex);
        }

    })
}

function isOtpCorrect(email, otp) {
        return new Promise((resolve, reject) => {
        // Get the user verification data from the database
        const sql = `SELECT * FROM admin_User_Verification WHERE email = ?`;
        connection.query(sql, [email], (error, results) => {
            if (error) {
            reject(error);
            } else {
            if (results.length === 0) {
                resolve({isActionSuccess:false,message:'User not found'});
            } else {
                const userVerificationData = results[0];
                if (userVerificationData.otp == otp && userVerificationData.expiryTimestamp > new Date()) {
                // If OTP matches and not expired, update isMatched to true
                const updateSql = `UPDATE admin_User_Verification SET isMatched = TRUE WHERE email = ?`;
                connection.query(updateSql, [email], (error) => {
                    if (error) {
                    reject(error);
                    } else {
                    resolve({ isActionSuccess: true });
                    }
                });
                } else if (userVerificationData.expiryTimestamp <= new Date()) {
                // If OTP has expired
                resolve({isActionSuccess:false,message:'OTP has expired'});
                } else {
                // If OTP is incorrect
                resolve({isActionSuccess:false,message:'Incorrect OTP'});
                }
            }
            }
        });
        });
  }
  

app.get("/validateOtp",async (req,res)=>
{
    if(req.body.otp != undefined && req.body.otp.length>0 && req.body.email!=undefined && req.body.email.length > 0)
    {
        const isCorrect= await isOtpCorrect(req.body.email,req.body.otp);
       if(isCorrect.isActionSuccess)
       {
        res.status(200).json({message:"yes validated"});
       }
       else{
        res.status(400).json({message:isCorrect.message});
       }
    }
    else{
        res.status(400).json({message:"Invalid parameters received"});
    }
})

function isAdminEmailAuthenticated(email) {
    return new Promise((resolve, reject) => {
      // Check if email exists in the database
      const checkEmailSql = `SELECT * FROM admin_user_verification WHERE email = ?`;
      connection.query(checkEmailSql, [email], (error, results) => {
        if (error) {
          reject(error);
        } else {
          if (results.length === 0) {
            // Email does not exist, return false
            resolve({isActionSuccess:false,message:"Please authenticate your email by hitting /validateAdminAccount route with your email address"});
          } else {
            const userVerificationData = results[0];
            if (userVerificationData.isMatched) {
              // If isMatched is true, email is authenticated
              resolve({isActionSuccess:true});
            } else {
              // If isMatched is false, email is not authenticated
              resolve({isActionSuccess:false,message:"This email is not authenticated in our system"});
            }
          }
        }
      });
    });
  }


  function validateAdminAccountParameters(name, email, password,phone_number, photo, bio) {
    return new Promise((resolve, reject) => {
        
            let returnObject={isValid:false};
            if(!name)
            {
                returnObject.message="Please provide the name";

            }
            else if(!email)
            {
                returnObject.message="Please provide the email";

            }
            else if(email && !/\S+@\S+\.\S+/.test(email))
            {
                returnObject.message="Invalid email format";
                 
            }
            else if(!phone_number)
            {
                returnObject.message="Please provide phone_number";

            }
            else if(phone_number && !/^(\+91)?\d{10}$/.test(phone_number))
            {
                returnObject.message="Invalid phone number format";
            }
            else if(!password)
            {
                returnObject.message="Please provide the password";
            }
            else if(password && !/(?=.*\d)(?=.*[A-Z])(?=.*\W).{8,}/.test(password))
            {
                returnObject.message="Password must contain at least one special character, one capital letter, and should be atleast 8 characters long";
               
            }
            else if (!name && !email && !phone_number && !photo && !bio) {
               
                returnObject.message="Please provide at least one parameter to update"; 
               
            } else {
              
                returnObject.isValid=true;
              
            }
            resolve(returnObject);
        });
}


  app.post("/registerAdminAccount",async (req,res)=>
{
    const { name, email, password,phone_number,photo,bio } = req.body;
    let returnObject={isActionSuccess:false};
    validateAdminAccountParameters(name,email,password,phone_number,photo,bio).then(async function(result)
    {
        if(result.isValid)
        {
            let result=await isAdminEmailAuthenticated(email);
            if(result.isActionSuccess)
            {
                bcrypt.hash(password, 10).then(async (hash) => {
                    createAccountInDb(name,email,hash,"admin",phone_number,photo,bio)
                        .then((result) => {
                          if(result.isActionSuccess)
                          {
                             const maxAge = 60 * 5; 
                              const token = jwt.sign(
                                { id: result.insertedId},
                                SECRET_KEY,
                                {
                                  expiresIn: maxAge, // 5min in sec
                                }
                              );
                             
                              res.status(201).json({
                                isActionSuccess:true,
                                id:result.insertedId,
                                message: "User successfully created",
                                token:token
                              });
                  
                          }
                          else{
                              res.status(400).json({
                                  isActionSuccess:false,
                                  error:result.error,
                                  message:result.message
                              })
                          }
                         
                        })
                        .catch((error) =>
                          res.status(400).json({
                            message: "User not successful created",
                            error: error.message,
                          })
                        );
                  
                  })

            }
            else{
                returnObject.message=result.message;
                res.status(400).json({message:returnObject.message});
            }

        }
        else{
            returnObject.message=result.message;
            res.status(400).json({message:returnObject.message});
            
        }

    })
    .catch((ex) =>
    {
        res.status(400).json({message:ex});
    })
   


})

app.post("/validateAdminAccount",async (req, res) => {
            if(req.body.email && req.body.email.length > 0)
            {
                if (!/\S+@\S+\.\S+/.test(req.body.email)) {
                    return res.status(400).json({ error: 'Invalid email format' });
                }
                else{
                    sendMailAndSaveDataInDb(req.body.email).then(function(result)
                    {
                        if(result.isActionSuccess)
                        {

                            res.status(200).json({message:"One time password (otp) has been sent to your email (might be in your spam) which will expire in next 5 minutes.So,please verify your email"});
                        }
                        else{
                            res.status(500).json({error:result.message});
                        }
                    })
                }  
            }
            else{
                res.send(400).json({message:"Please provide an email address"});
            }

    });







