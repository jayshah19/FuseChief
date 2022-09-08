const express = require('express')
const fs = require('fs')
const app = express()
var pathe = require('path')
const multer = require('multer')
const mongoose = require("mongoose")
const bodyParser = require("body-parser")
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken') 

const JWT_SECRET = ';oidhjf;lkdahjsj li;furqw[oitvufenoioungfoisaud[oifusao;+'

const {google} = require('googleapis')
const Oauth2Data = require('./credentials.json')
const CLIENT_ID = Oauth2Data.web.client_id
const CLIENT_SECRET = Oauth2Data.web.client_secret
const REDIRECT_URI = Oauth2Data.web.redirect_uris[0]
const SCOPES = "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email"


var normAuth = false
var gAuth1 = false
var gAuth2 = false
var UserInfo = new Object();

var files1,files2

const oAuth2Client1 = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI
)

const oAuth2Client2 = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI
)


//multer file storage and stuff
var Storage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, "./userFiles");
  },
  filename: function (req, file, callback) {
    callback(null, file.fieldname + "_" + Date.now() + "_" + file.originalname);
  },
});

var upload = multer({
  storage: Storage,
}).single("file"); //Field name and max count

//end multer stuff here

app.use(express.static(pathe.join(__dirname, 'public')));
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
  extended:true
}))


mongoose.connect('mongodb://localhost:27017/fusechief',{
  useNewUrlParser:true,
  useUnifiedTopology:true
});

async function myfunc(req,res){
  try {

    if(!gAuth1){
      var url1 = oAuth2Client1.generateAuthUrl({
        access_type:'offline',
        scope:SCOPES
      })
    }
    if(!gAuth2){
      var url2 = oAuth2Client2.generateAuthUrl({
        access_type:'offline',
        scope:SCOPES
      })
    }

    if(gAuth1)
    {
      var account1 = google.oauth2({
        auth:oAuth2Client1,
        version:'v2'
      })
      account1.userinfo.get(function(err,response){
        if(err) throw err
        UserInfo.name1 = response.data.name
        UserInfo.pic1 = response.data.picture
        UserInfo.email1 = response.data.email
      })

      const drive = google.drive({
        version:'v3',
        auth: oAuth2Client1
      })

      drive.files.list({}, (err, res) => {
        if (err) throw err;
        files1 = res.data.files;
      });
    }
    

    if(gAuth2)
    {
      var account2 = google.oauth2({
        auth:oAuth2Client2,
        version:'v2'
      })
      account2.userinfo.get(function(err,response){
        if(err) throw err
        UserInfo.name2 = response.data.name
        UserInfo.pic2 = response.data.picture
        UserInfo.email2 = response.data.email
      })

      const drive = google.drive({
        version: 'v3',
        auth: oAuth2Client2
      })

      drive.files.list({}, (err, res) => {
        if (err) throw err;
        files2 = res.data.files;
      });
    }
    

    if(gAuth1 && !gAuth2)
    {    
      //console.log(UserInfo)
      await new Promise(resolve => setTimeout(resolve, 1000));     
      await res.render("Dashboard",{Information:UserInfo, url1:url1, url2:url2, ga1:gAuth1, ga2:gAuth2, files1:files1, files2:files2})
    }
    else if(gAuth2 && !gAuth1)
    {    
      //console.log(UserInfo)
      await new Promise(resolve => setTimeout(resolve, 1000)); 
      await res.render("Dashboard",{Information:UserInfo, url1:url1, url2:url2, ga1:gAuth1, ga2:gAuth2, files1:files1, files2:files2})
    }
    else if(gAuth1 && gAuth2)
    {      
      //console.log(UserInfo)
      await new Promise(resolve => setTimeout(resolve, 1000)); 
      await res.render("Dashboard",{Information:UserInfo, url1:url1, url2:url2, ga1:gAuth1, ga2:gAuth2, files1:files1, files2:files2})
    }
    else{
      await new Promise(resolve => setTimeout(resolve, 1000)); 
      await res.render("Dashboard",{Information:UserInfo, url1:url1, url2:url2, ga1:gAuth1, ga2:gAuth2, files1:files1, files2:files2})
    }
    
  } catch (error) {
    console.log(error)
  }
}


app.set("view engine", "ejs")
app.get('/', async (req,res) => {

  if(!normAuth)
  {
    res.render("login")
  }
  else{
    await myfunc(req,res);
  }
})



app.post("/signin", async (req,res) => {

  const {email,password} = req.body
  const user = await User.findOne({email}).lean()
  if(!user){
    return res.json({status:'error', error: 'Invalid username'})
  }
  if(await bcrypt.compare(password, user.password)){
    //email password combination successful
    const token = jwt.sign({
      id: user._id,
      username: user.username
    }, JWT_SECRET)
    normAuth = true;
    UserInfo.name = user.username;
    UserInfo.id = user._id;
    return res.json({status:'ok', data: token})
  }
    return res.json({status:'error', error: 'Invalid password'})
})

app.get('/Register', (req,res) => {
  res.render("Register")
})

app.post("/signup",async (req,res)=>{
  console.log(req.body)
  const {username, email, password: plainTextPassword} = req.body

  if(!username || typeof username != 'string'){
    return res.json({ status: 'error', error: 'Invalid Username'})
  }

  if(!email || typeof email != 'string'){
    return res.json({ status: 'error', error: 'Invalid email'})
  }

  if(!plainTextPassword || typeof plainTextPassword != 'string'){
    return res.json({ status: 'error', error: 'Invalid password'})
  }

  if(plainTextPassword.length < 5){
    return res.json({
      status: 'error',
      error: 'Password too small. Should be atleast 6 characters long'
    })
  }

  const password = await bcrypt.hash(plainTextPassword, 10)

  try {
    const response = await User.create({
      username,
      email,
      password
    })
    console.log('User Created Successfully: ', response)
  } catch (error) {
    if(error.code === 11000){
      //duplicate key
      return res.json({status:'error', error: 'Email already in use'})
    }
    throw error
  }
  console.log(await bcrypt.hash(password, 10))

  res.json({ status: 'ok' })

})


//google auth stuff

app.get('/google/callback', (req,res) =>{

  if(!gAuth1)
  {
    const code = req.query.code
    if(code){
      //get an access token
      oAuth2Client1.getToken(code,function(err,tokens){
        if(err){
          console.log("Error in Authenticating")
          console.log(err)
        }
        else{
          console.log("Successfully authenticated")

          oAuth2Client1.setCredentials(tokens)

          gAuth1 = true
          res.redirect('/')
        }
      })
    }
  }
  else{
    const code = req.query.code
    if(code){
      //get an access token
      oAuth2Client2.getToken(code,function(err,tokens){
        if(err){
          console.log("Error in Authenticating")
          console.log(err)
        }
        else{
          console.log("Successfully authenticated")

          oAuth2Client2.setCredentials(tokens)
          gAuth2 = true
          res.redirect('/')
        }
      })
    }
  }

})

app.post('/upload', (req,res) => {
  upload(req,res,function(err){
    if(err) throw err
    console.log(req.file.path)
    const drive = google.drive({
      version:'v3',
      auth: oAuth2Client1
    })

    const filemetadata = {
      name:req.file.filename
    }
    const media = {
      mimeType:req.file.mimeType,
      body:fs.createReadStream(req.file.path)
    }

    drive.files.create({
      resource:filemetadata,
      media:media,
      fields:"id"
    },(err,file) => {
      if(err) throw err
      //delete the file from local folder
      fs.unlinkSync(req.file.path)
      res.redirect("/")
    })
  })
})

app.post('/download', async (req,res) => {

  const {fid} = req.body

  var dir = `./downloads`; // directory from where node.js will look for downloaded file from google drive

  var fileId = fid // Desired file id to download from  google drive

  var dest = fs.createWriteStream('./downloads/file_1658889489675_Updated Jay Shah IBM Cover.pdf'); // file path where google drive function will save the file

  const drive = google.drive({ version: 'v3', oAuth2Client1 }); // Authenticating drive API

  let progress = 0; // This will contain the download progress amount

  // Uploading Single image to drive
  drive.files
    .get({ fileId, alt: 'media' }, { responseType: 'stream' })
    .then((driveResponse) => {
      driveResponse.data
        .on('end', () => {
          console.log('\nDone downloading file.');
          const file = `${dir}/file_1658889489675_Updated Jay Shah IBM Cover.pdf`; // file path from where node.js will send file to the requested user
          res.download(file); // Set disposition and send it.
        })
        .on('error', (err) => {
          console.error('Error downloading file.');
        })
        .on('data', (d) => {
          progress += d.length;
          if (process.stdout.isTTY) {
            process.stdout.clearLine();
            process.stdout.cursorTo(0);
            process.stdout.write(`Downloaded ${progress} bytes`);
          }
        })
        .pipe(dest);
    })
    .catch((err) => console.log(err));



})


app.listen(3000, () => {
  console.log("App started on port 3000")
})
