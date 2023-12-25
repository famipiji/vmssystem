//mongoDB
const { MongoClient} = require("mongodb");
const uri = "mongodb+srv://fakhrul:1235@clusterfakhrul.bigkwnk.mongodb.net/"
const  client = new MongoClient(uri)
//express
const express = require('express')
var jwt = require('jsonwebtoken')
const app = express()
const port = process.env.PORT ||3000

//swagger
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'VMS API',
            version: '1.0.0'
        },
        components: {  // Add 'components' section
            securitySchemes: {  // Define 'securitySchemes'
                bearerAuth: {  // Define 'bearerAuth'
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
//bcrypt
const bcrypt = require('bcrypt');
const saltRounds = 10;
var hashed;
//token
var token
const privatekey = "PRXWGaming"
var checkpassword;

app.use(express.json());

/**
 * @swagger
 * /loginOwner:
 *   post:
 *     summary: "Owner Login"
 *     description: "Login for owner using ID number and password"
 *     tags:
 *       - Authentication
 *     parameters:
 *       - in: body
 *         name: credentials
 *         description: "Owner credentials"
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             idNumber:
 *               type: string
 *               description: "Owner's ID number"
 *             password:
 *               type: string
 *               description: "Owner's password"
 *     responses:
 *       '200':
 *         description: "Owner logged in successfully"
 *       '400':
 *         description: "Invalid credentials or error in login process"
 *     consumes:
 *       - "application/json"
 *     produces:
 *       - "application/json"
 */
//login as Owner
app.post( '/loginOwner',async function (req, res) {
  let {idNumber, password} = req.body
  const salt = await bcrypt.genSalt(saltRounds)
  hashed = await bcrypt.hash(password, salt)
  await loginOwner(idNumber, hashed)
})
/**
 * @swagger
 * /loginSecurity:
 *   post:
 *     summary: "Security Login"
 *     description: "Login for security personnel using ID number and password"
 *     tags:
 *       - Authentication
 *     parameters:
 *       - in: body
 *         name: credentials
 *         description: "Security personnel credentials"
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             idNumber:
 *               type: string
 *               description: "Security personnel's ID number"
 *             password:
 *               type: string
 *               description: "Security personnel's password"
 *     responses:
 *       '200':
 *         description: "Security personnel logged in successfully"
 *       '400':
 *         description: "Invalid credentials or error in login process"
 *     consumes:
 *       - "application/json"
 *     produces:
 *       - "application/json"
 */
//login as Security
app.post( '/loginSecurity',async function (req, res) {
  let {idNumber, password} = req.body
  const salt = await bcrypt.genSalt(saltRounds)
  hashed = await bcrypt.hash(password, salt)
  await loginSecurity(idNumber, hashed)
})
/**
 * @swagger
 * /registerOwner:
 *   post:
 *     summary: "Register Owner"
 *     description: "Register a new owner in the system"
 *     tags:
 *       - Owner Management
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         type: string
 *         description: "Bearer token for authentication"
 *         required: true
 *       - in: body
 *         name: ownerDetails
 *         description: "Owner details for registration"
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             role:
 *               type: string
 *               description: "Role of the owner (e.g., 'security')"
 *             name:
 *               type: string
 *               description: "Name of the owner"
 *             idNumber:
 *               type: string
 *               description: "ID number of the owner"
 *             email:
 *               type: string
 *               description: "Email of the owner"
 *             password:
 *               type: string
 *               description: "Password for the owner"
 *             phoneNumber:
 *               type: string
 *               description: "Phone number of the owner"
 *     responses:
 *       '200':
 *         description: "Owner registered successfully"
 *       '400':
 *         description: "Invalid token or error in registration process"
 *       '401':
 *         description: "Unauthorized - Invalid token or insufficient permissions"
 *     consumes:
 *       - "application/json"
 *     produces:
 *       - "application/json"
 *   securityDefinitions:
 *     bearerAuth:
 *       type: apiKey
 *       name: Authorization
 *       in: header
 */
//register Owner
app.post('/registerOwner', async function (req, res){
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  jwt.verify(token, privatekey, async function(err, decoded) {
    console.log(decoded)
    if (await decoded.role == "security"){
      const data = req.body
      res.send(
        registerOwner(
          data.role,
          data.name,
          data.idNumber,
          data.email,
          data.password,
          data.phoneNumber
        )
      )
    }else{
      console.log("You have no access to register an owner!")
    }
})
})
/**
 * @swagger
 * /checkinVisitor:
 *   post:
 *     summary: "Check-in Visitor"
 *     description: "Check in a visitor to the premises"
 *     tags:
 *       - Visitor Management
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         type: string
 *         description: "Bearer token for authentication"
 *         required: true
 *       - in: body
 *         name: visitorDetails
 *         description: "Visitor details for check-in"
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             role:
 *               type: string
 *               description: "Role of the requester (owner or security)"
 *             name:
 *               type: string
 *               description: "Name of the visitor"
 *             idNumber:
 *               type: string
 *               description: "ID number of the visitor"
 *             documentType:
 *               type: string
 *               description: "Type of document presented by the visitor"
 *             gender:
 *               type: string
 *               description: "Gender of the visitor"
 *             birthDate:
 *               type: string
 *               format: date
 *               description: "Birthdate of the visitor"
 *             age:
 *               type: integer
 *               description: "Age of the visitor"
 *             documentExpiry:
 *               type: string
 *               format: date
 *               description: "Expiry date of the presented document"
 *             company:
 *               type: string
 *               description: "Company or organization the visitor represents"
 *             TelephoneNumber:
 *               type: string
 *               description: "Telephone number of the visitor"
 *             vehicleNumber:
 *               type: string
 *               description: "Vehicle number of the visitor"
 *             category:
 *               type: string
 *               description: "Category or purpose of the visit"
 *             ethnicity:
 *               type: string
 *               description: "Ethnicity of the visitor"
 *             photoAttributes:
 *               type: string
 *               description: "Additional attributes related to visitor's photo"
 *             passNumber:
 *               type: string
 *               description: "Pass number assigned to the visitor"
 *     responses:
 *       '200':
 *         description: "Visitor checked in successfully"
 *       '400':
 *         description: "Invalid token or error in check-in process"
 *       '401':
 *         description: "Unauthorized - Invalid token or insufficient permissions"
 *     consumes:
 *       - "application/json"
 *     produces:
 *       - "application/json"
 *   securityDefinitions:
 *     bearerAuth:
 *       type: apiKey
 *       name: Authorization
 *       in: header
 */
//checkin visitor
app.post('/checkinVisitor', async function (req, res) {
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  
  jwt.verify(token, privatekey, async function(err, decoded) {
    if (err) {
      console.log("Error decoding token:", err);
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    console.log(decoded);
    
    if (decoded && (decoded.role === "owner" || decoded.role === "security")) {
      const data = req.body;
      
      res.send(
        checkinVisitor(
          data.role,
          data.name,
          data.idNumber,
          data.documentType,
          data.gender,
          data.birthDate,
          data.age,
          data.documentExpiry,
          data.company,
          data.TelephoneNumber,
          data.vehicleNumber,
          data.category,
          data.ethnicity,
          data.photoAttributes,
          data.passNumber
        )
      );
    } else {
      console.log("You have no access to check in a visitor!");
    }
  });
});
/**
 * @swagger
 * /viewVisitor:
 *   get:
 *     summary: "View Visitors"
 *     description: "View a list of visitors"
 *     tags:
 *       - Visitor Management
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         type: string
 *         description: "Bearer token for authentication"
 *         required: true
 *     responses:
 *       '200':
 *         description: "List of visitors retrieved successfully"
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/Visitor'
 *       '400':
 *         description: "Invalid token or error in retrieving visitors"
 *       '401':
 *         description: "Unauthorized - Invalid token or insufficient permissions"
 *     produces:
 *       - "application/json"
 *   securityDefinitions:
 *     bearerAuth:
 *       type: apiKey
 *       name: Authorization
 *       in: header
 * definitions:
 *   Visitor:
 *     type: object
 *     properties:
 *       name:
 *         type: string
 *         description: "Name of the visitor"
 *       idNumber:
 *         type: string
 *         description: "ID number of the visitor"
 *       documentType:
 *         type: string
 *         description: "Type of document presented by the visitor"
 *       gender:
 *         type: string
 *         description: "Gender of the visitor"
 *       birthDate:
 *         type: string
 *         format: date
 *         description: "Birthdate of the visitor"
 *       age:
 *         type: integer
 *         description: "Age of the visitor"
 *       documentExpiry:
 *         type: string
 *         format: date
 *         description: "Expiry date of the presented document"
 *       company:
 *         type: string
 *         description: "Company or organization the visitor represents"
 *       TelephoneNumber:
 *         type: string
 *         description: "Telephone number of the visitor"
 *       vehicleNumber:
 *         type: string
 *         description: "Vehicle number of the visitor"
 *       category:
 *         type: string
 *         description: "Category or purpose of the visit"
 *       ethnicity:
 *         type: string
 *         description: "Ethnicity of the visitor"
 *       photoAttributes:
 *         type: string
 *         description: "Additional attributes related to visitor's photo"
 *       passNumber:
 *         type: string
 *         description: "Pass number assigned to the visitor"
 */
//view visitor 
app.get('/viewVisitor', async (req, res) => {
  await client.connect();
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  
  jwt.verify(token, privatekey, async function(err, decoded) {
    console.log(decoded);
    
    if (decoded && (decoded.role === "owner" || decoded.role === "security")) {
      const visitors = await client.db("assignmentCondo").collection("visitor").find({}).toArray();
      
      console.log(visitors); // Print visitors in the terminal
      
      res.send(visitors);
    }
  });
});

/**
 * @swagger
 * /changePassNumber:
 *   post:
 *     summary: "Change Pass Number"
 *     description: "Change the pass number for a user with security role"
 *     tags:
 *       - Security Management
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         type: string
 *         description: "Bearer token for authentication"
 *         required: true
 *       - in: body
 *         name: passNumberChange
 *         description: "Pass number change details"
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             savedidNumber:
 *               type: string
 *               description: "ID number of the user whose pass number needs to be changed"
 *             newpassNumber:
 *               type: string
 *               description: "New pass number to be assigned to the user"
 *     responses:
 *       '200':
 *         description: "Pass number changed successfully"
 *       '400':
 *         description: "Invalid token or error in pass number change process"
 *       '401':
 *         description: "Unauthorized - Invalid token or insufficient permissions"
 *       '403':
 *         description: "Forbidden - User does not have access to change the pass number"
 *     consumes:
 *       - "application/json"
 *     produces:
 *       - "application/json"
 *   securityDefinitions:
 *     bearerAuth:
 *       type: apiKey
 *       name: Authorization
 *       in: header
 */
//change pass number
app.post('/changePassNumber', async function (req, res) {
  let header = req.headers.authorization;
  let token = header.split(' ')[1];

  jwt.verify(token, privatekey, async function(err, decoded) {
    if (err) {
      console.log("Error decoding token:", err);
      return res.status(401).json({ error: 'Unauthorized' });
    }

    console.log(decoded);

    if (decoded.role === "security") {
      const { savedidNumber, newpassNumber } = req.body;
      await changePassNumber(savedidNumber, newpassNumber);
      res.send(req.body);
    } else {
      console.log("You have no access to change the pass number!");
      return res.status(403).json({ error: 'Forbidden' });
    }
  });
});

/**
 * @swagger
 * /checkoutVisitor:
 *   post:
 *     summary: "Check-out Visitor"
 *     description: "Check out a visitor from the premises"
 *     tags:
 *       - Visitor Management
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         type: string
 *         description: "Bearer token for authentication"
 *         required: true
 *       - in: body
 *         name: visitorCheckout
 *         description: "Visitor checkout details"
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             name:
 *               type: string
 *               description: "Name of the visitor"
 *             idNumber:
 *               type: string
 *               description: "ID number of the visitor"
 *     responses:
 *       '200':
 *         description: "Visitor checked out successfully"
 *       '400':
 *         description: "Invalid token or error in check-out process"
 *       '401':
 *         description: "Unauthorized - Invalid token or insufficient permissions"
 *       '403':
 *         description: "Forbidden - User does not have access to check out the visitor"
 *     consumes:
 *       - "application/json"
 *     produces:
 *       - "application/json"
 *   securityDefinitions:
 *     bearerAuth:
 *       type: apiKey
 *       name: Authorization
 *       in: header
 */
//checkout visitor
app.post('/checkoutVisitor', async function (req, res) {
  let header = req.headers.authorization;
  let token = header.split(' ')[1];

  jwt.verify(token, privatekey, async function(err, decoded) {
    console.log(decoded);

    if (decoded && decoded.role === "security") {
      const { name, idNumber } = req.body;
      await checkoutVisitor(name, idNumber);
      res.send(req.body);
    } else {
      console.log("You have no access to check out the visitor!");
      res.status(403).send("Forbidden");
    }
  });
});


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

//////////FUNCTION//////////

//CREATE(createListing for owner)
async function createListing1(client, newListing){
  const result = await client.db("assignmentCondo").collection("owner").insertOne(newListing);
  console.log(`New listing created with the following id: ${result.insertedId}`);
}

//CREATE(createListing for visitor)
async function createListing2(client, newListing){
  const result = await client.db("assignmentCondo").collection("visitor").insertOne(newListing);
  console.log(`New listing created with the following id: ${result.insertedId}`);
}

//READ(login as Owner)
async function loginOwner(idNumber, hashed){
  await client.connect()
  const result = await client.db("assignmentCondo").collection("owner").findOne({ idNumber: idNumber });
  const role = await result.role
  if (result) {
    //BCRYPT verify password
    bcrypt.compare(result.password, hashed, function(err, result){
      if(result == true){
        res.send("Access granted. Welcome/nPassword:",hashed,"/nRole:", role,"/nToken:", token)
        token = jwt.sign({idNumber: idNumber, role: role}, privatekey);
      }else{
        console.log("Wrong password")
      }
    });
  } 
  else {
      console.log("Owner not registered")
  }
}

//READ(login as Security)
async function loginSecurity(idNumber, hashed){
  await client.connect()
  const result = await client.db("assignmentCondo").collection("security").findOne({ idNumber: idNumber });
  const role = await result.role
  if (result) {
    //BCRYPT verify password
    bcrypt.compare(result.password, hashed, function(err, result){
      if(result == true){
        console.log("Access granted. Welcome")
        console.log("Password:", hashed)
        console.log("Role:", role)
        token = jwt.sign({idNumber: idNumber, role: role}, privatekey);
        console.log("Token:", token);
      }else{
        console.log("Wrong password")
      }
    });
  }
  else {
      console.log("Security not registered")
  }
}

//CREATE(register Owner)
async function registerOwner(newrole, newname, newidNumber, newemail, newpassword, newphoneNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("owner").findOne({idNumber: newidNumber})
  if(exist){
    console.log("Owner has already registered")
  }else{
    await createListing1(client,
      {
        role: newrole,
        name: newname,
        idNumber: newidNumber,
        email: newemail,
        password: newpassword,
        phoneNumber: newphoneNumber
      }
    );
    console.log("Owner registered sucessfully")
  }
}

//CREATE(checkin Visitor)
async function checkinVisitor(newrole, newname, newidNumber, newdocumentType, newgender, newbirthDate, 
                        newage, newdocumentExpiry, newcompany, newTelephoneNumber, newvehicleNumber,
                        newcategory, newethnicity, newphotoAttributes, newpassNumber){
  //TODO: Check if username exist
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({name: newname})
  if(exist){
      console.log("Visitor has already checked in")
  }else{
      await createListing2(client,
        {
          role: newrole,
          name: newname,
          idNumber: newidNumber,
          documentType: newdocumentType,
          gender: newgender,
          birthDate:newbirthDate,
          age: newage,
          documentExpiry: newdocumentExpiry,
          company: newcompany,
          TelephoneNumber: newTelephoneNumber,
          vehicleNumber: newvehicleNumber,
          category: newcategory,
          ethnicity: newethnicity,
          photoAttributes: newphotoAttributes,
          passNumber: newpassNumber 
        }
      );
      console.log("Checked in successfully!")
  }
} 

//UPDATE(change pass number)
async function changePassNumber(savedidNumber, newpassNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: savedidNumber})
  if(exist){
    await client.db("assignmentCondo").collection("visitor").updateOne({idNumber: savedidNumber}, {$set: {passNumber: newpassNumber}})
    console.log("Visitor's pass number has changed successfuly.")
  }else{
    console.log("The visitor does not exist.")
  }
}

//DELETE(delete visitor)
async function checkoutVisitor(oldname, oldidNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({name: oldname})
  if(exist){
    checkidNumber = await exist.idNumber;
    if(oldidNumber == checkidNumber){
      await client.db("assignmentCondo").collection("visitor").deleteOne({name: oldname})
      console.log("Visitor account deleted successfully.")
    }else{
      console.log("ID number is incorrect")
    }
  }else{
    console.log("Visitor does not exist.")
  }
}

//Verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'PRXgaming', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }
    res.user = decoded;
    next();
  });
}