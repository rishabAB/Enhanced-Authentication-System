In this project I am assuming you have nodejs ,mysql workbench and postman account installed in your system
 
 Firstly run these queries in you sql.

<!-- Q1 -->
  CREATE database auth;

  <!-- Q2 -->
    use auth;

<!-- Q3 -->

CREATE TABLE user_accounts (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    bio TEXT,
    phone_number VARCHAR(15) DEFAULT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) DEFAULT NULL,
    photo VARCHAR(255) DEFAULT NULL,
    account_type ENUM('public', 'private', 'admin')  DEFAULT 'public',
    isUserLoggedIn BOOLEAN DEFAULT false,
    isGoogleAuthenticated BOOLEAN DEFAULT false
);

<!-- Q4 -->

CREATE TABLE admin_User_Verification (
    email VARCHAR(255) NOT NULL,
    otp INT NOT NULL,
    isMatched BOOLEAN NOT NULL DEFAULT FALSE,
    expiryTimestamp TIMESTAMP NOT NULL,
    PRIMARY KEY (email)
);

Now please install all the modules so execute 
npm i in your terminal wrt this directory

now run the file generateSecret.js just one time when you open this project


Now add your sql connection strings which is your user and password which is in the beggining of app.js which is main file.

Then start the main file which is app.js

Then there are different routes for different things to execute

MAKE SURE TO CHECK POSTMAN COLLECTION 
PLEASE READ THE POSTMAN INSTRUCTIONS CAREFULLY IN EACH REQUEST

PLEASE NOTE THERE IS A RATE LIMITING FEATURE WHICH LIMITS NUMBER OF HITS ON THIS API 
SO YOU CAN HIT MAX 5 ROUTES WITHING  MINUTE

ADDITIONALLY TYOU WILL GET A TOKEN WHEN YOU CREATE/LOGIN FROM AN ACCOUNT THAT WILL EXPIRE
IN 5 MINUTES THEN YOU NEED TO LOGIN AGAIN IF THAT EXPIRES 

For creating a user of type admin you need to hit 
Step 1 this route http://localhost:7000/validateAdminAccount
Make sure you provide correct email beacause you'll get an otp in that email
Step 2 http://localhost:7000/validateOtp
Then in order to validate enter your otp and email id 
Step 3 http://localhost:7000/registerAdminAccount
Then You will be able to create and admin account 


So,In order to execute please begin with postman collection.

PLEASE NOTE THERE IS NO DIRECT ROUTE TO HIT FOR SIGN IN WITH GOOGLE YOU NEED UI IN ORDER TO
EXECUTE YOU NEED UI SO PLEASE VISIT http://localhost:7000 URL IN ORDER TO LOGIN/REGISTER WITH GOOGLE 