//mongoDB
const { MongoClient} = require("mongodb");
const uri = "mongodb+srv://fahmi:1234@assignmentcondo.q2tnhgu.mongodb.net/?retryWrites=true&w=majority"
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

//login as Host
/**
 * @swagger
 * /loginHost:
 *   post:
 *     summary: Authenticate Host
 *     description: Login with identification number and password
 *     tags: [Host]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               idNumber:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
app.post( '/loginHost',async function (req, res) {
  let {idNumber, password} = req.body;
  const hashed = await generateHash(password);
  await loginHost(res, idNumber, hashed)
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

//login as Admin
/**
 * @swagger
 * /loginAdmin:
 *   post:
 *     summary: Authenticate administrator personnel
 *     description: Login with identification number and password
 *     tags: [Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               idNumber:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
app.post( '/loginAdmin',async function (req, res) {
  let {idNumber, password} = req.body
  const hashed = await generateHash(password);
  await loginAdmin(res, idNumber, hashed)
})


//register Host
/**
 * @swagger
 * /registerHost:
 *   post:
 *     summary: Register an Host
 *     description: Register a new Host with security role
 *     tags: [Host]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *               name:
 *                 type: string
 *               idNumber:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               phoneNumber:
 *                 type: string
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Host registered successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to register an Host
 */
app.post('/registerHost', async function (req, res){
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  jwt.verify(token, privatekey, async function(err, decoded) {
    console.log(decoded)
    if (await decoded.role == "security"){
      const data = req.body
      res.send(
        registerHost(
          data.role,
          data.name,
          data.idNumber,
          data.email,
          data.password,
          data.phoneNumber
        )
      )
    }else{
      console.log("You have no access to register an Host!")
    }
})
})


//retrieve Visitor info
/**
 * @swagger
 * /retrieveVisitor:
 *   post:
 *     summary: Authenticate visitor
 *     description: Login with identification number and password for a visitor to view pass
 *     tags: [Visitor]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               idNumber:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
app.post('/retrieveVisitor', async function(req, res){
  const {idNumber, password} = req.body;
  retrieveVisitor(res, idNumber , password);
});

/**
 * @swagger
 * /viewVisitor:
 *   post:
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
app.post('/viewVisitor', async function(req, res){
  var token = req.header('Authorization').split(" ")[1];
  try {
      var decoded = jwt.verify(token, privatekey);
      console.log(decoded.role);
      res.send(await visitor(decoded.idNumber, decoded.role));
    } catch(err) {
      res.send("Error!");
    }
})

//register visitor
/**
 * @swagger
 * /createpassVisitor:
 *   post:
 *     summary: Create a visitor pass
 *     description: Create a new visitor pass (accessible to Hosts and security personnel)
 *     tags: [Host, Security]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *               name:
 *                 type: string
 *               idNumber:
 *                 type: string
 *               documentType:
 *                 type: string
 *               gender:
 *                 type: string
 *               birthDate:
 *                 type: string
 *               age:
 *                 type: number
 *               documentExpiry:
 *                 type: string
 *               company:
 *                 type: string
 *               TelephoneNumber:
 *                 type: string
 *               vehicleNumber:
 *                 type: string
 *               category:
 *                 type: string
 *               ethnicity:
 *                 type: string
 *               photoAttributes:
 *                 type: string
 *               passNumber:
 *                 type: string
 *               password:
 *                type: string
 *     responses:
 *       '200':
 *         description: Visitor registered successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to register a visitor
 */
app.post('/createpassVisitor', async function(req, res){
  var token = req.header('Authorization').split(" ")[1];
  let decoded;

  try {
      decoded = jwt.verify(token, privatekey);
      console.log(decoded.role);
  } catch(err) {
      console.log("Error decoding token:", err.message);
      return res.status(401).send("Unauthorized"); // Send a 401 Unauthorized response
  }

  if (decoded && (decoded.role === "Host" || decoded.role === "security")){
      const {
          role, name, idNumber, documentType, gender, birthDate, age, 
          documentExpiry, company, TelephoneNumber, vehicleNumber, 
          category, ethnicity, photoAttributes, passNumber, password
      } = req.body;

      await createpassVisitor(role, name, idNumber, documentType, gender, birthDate, 
                              age, documentExpiry, company, TelephoneNumber, 
                              vehicleNumber, category, ethnicity, photoAttributes, 
                              passNumber, password);
  } else {
      console.log("Access Denied!");
      res.status(403).send("Access Denied"); // Send a 403 Forbidden response
  }
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

//delete visitor
/**
 * @swagger
 * /deleteVisitor:
 *   post:
 *     summary: Delete a visitor
 *     description: Delete a visitor by name and ID number
 *     tags: [Host]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               idNumber:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Visitor deleted successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '500':
 *         description: Internal Server Error
 */
app.post('/deleteVisitor', async function (req, res){
  const {name, idNumber} = req.body
  await deleteVisitor(name, idNumber)
  res.send(req.body)
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})

//////////FUNCTIONS//////////

//Generate hash password
async function generateHash(password){
  const saltRounds = 10
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
}

//CREATE(createListing for Host)
async function createListing1(client, newListing){
  const result = await client.db("assignmentCondo").collection("owner").insertOne(newListing);
  console.log(`New listing created with this id: ${result.insertedId}`);
}

//CREATE(createListing for visitor)
async function createListing2(client, newListing){
  const result = await client.db("assignmentCondo").collection("visitor").insertOne(newListing);
  console.log(`New listing created with this id: ${result.insertedId}`);
}

//READ(login as Host)
async function loginHost(res, idNumber, hashed){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("owner").findOne({ idNumber: idNumber });
    if (exist) {
        const passwordMatch = await bcrypt.compare(exist.password, hashed);
        if (passwordMatch) {
            console.log("Login Success!\nRole: "+ exist.role);
            logs(idNumber, exist.name, exist.role);
            const token = jwt.sign({ idNumber: idNumber, role: exist.role }, privatekey);
            res.send("Token: " + token);
        } else {
            console.log("Wrong password!");
        }
    } else {
        console.log("Username not exist!");
    }
}

//READ(retrieve pass as visitor)
async function retrieveVisitor(res, idNumber, password){
  await client.connect();
    const exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: idNumber});
    if(exist){
        if(bcrypt.compare(password,await exist.password)){
        console.log("Welcome!");
        token = jwt.sign({ idNumber: idNumber, role: exist.role}, privatekey);
        res.send({
          "Token": token,
          "Visitor Info": exist
        });
        
        res.send(exist);
        await logs(id, exist.name, exist.role);
        }else{
            console.log("Wrong password!")
        }
    }else{
        console.log("Visitor not exist!");
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

//CREATE(register Host)
async function registerHost(newrole, newname, newidNumber, newemail, newpassword, newphoneNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("owner").findOne({idNumber: newidNumber})
  if(exist){
    console.log("Host has already registered")
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
    console.log("Host registered sucessfully")
  }
}

//READ(login as Admin)
async function loginAdmin(res,idNumber, hashed){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("admin").findOne({ idNumber: idNumber });
    if (exist) {
        const passwordMatch = await bcrypt.compare(exist.password, hashed);
        if (passwordMatch) {
            console.log("Login Success!\nRole: "+ exist.role);
            logs(idNumber, exist.name, exist.role);
            const token = jwt.sign({ idNumber: idNumber, role: exist.role }, privatekey);
            res.send("Token: " + token);
        } else {
            console.log("Wrong password!");
        }
    } else {
        console.log("Username not exist!");
    }
}

//view visitor
async function visitor(idNumber, role) {
  var exist;
  await client.connect();
  if(role == "Host" || role == "security"){
    exist = await client.db("assignmentCondo").collection("visitor").find({}).toArray();
  }
  else if(role == "visitor"){
    exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: idNumber});
  }
  return exist;
}

//CREATE(register Visitor)
async function createpassVisitor(newrole, newname, newidNumber, newdocumentType, newgender, newbirthDate, 
  newage, newdocumentExpiry, newcompany, newTelephoneNumber, newvehicleNumber,
  newcategory, newethnicity, newphotoAttributes, newpassNumber, password){
//TODO: Check if username exist
await client.connect()
const exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: newidNumber})
//hashed = await bcrypt.hash(password, 10);
if(exist){
console.log("Visitor has already registered")
}else{
await client.db("assignmentCondo").collection("visitor").insertOne(
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
passNumber: newpassNumber,
password: password 
}
);
console.log("Registered successfully!")
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
async function deleteVisitor(oldname, oldidNumber){
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