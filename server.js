const express = require('express');
const mysql = require('mysql');
 const cors = require('cors');
 const jwt = require('jsonwebtoken');
 const bcrypt = require('bcrypt');
 const cookieParser = require('cookie-parser');
 const salt = 10;

 const app = express();
 app.use(express.json());
 app.use(cors({
   origin:["http://localhost:8080"],
   methods:["POST","GET"],
   credentials: true,
 }));
 app.use(cookieParser());
 
 

 const db = mysql.createConnection({
    host:"localhost",
    user:"root",
    password:"",
    database:"signup_db"
 });


//register  
 app.post('/register',(req,res)=>{
      const sql = "INSERT INTO users(username,email,password,remember) VALUES (?)";
      bcrypt.hash(req.body.password.toString(),salt,(err,hash)=>{
         if(err) return res.json({Error:"error on password hashing"});
         const values = [
            req.body.username,
            req.body.email,
            hash,
            0
         ];
         db.query(sql,[values],(err, result)=>{
            if(err) return res.json({Error:"Inserting data error in server"});
            return res.json({status:"success"})
         })

         

      })
     
 })

 //login

 app.post('/login',(req,res)=>{
   const sql = "SELECT * FROM USERS WHERE email = ?";
   db.query(sql,[req.body.email],(err,result)=>{
      if(err) return res.json({Error:"Login error in server"});
      if(result.length > 0){
         // const pwd = result[0].password;
         bcrypt.compare(req.body.password,result[0].PASSWORD, (err,response)=>{
               if(err) return res.json({Error:"password compare error!"})
               if(response){
                  const username = result[0].USERNAME;
                  const token = jwt.sign({username},"jwt-secret-key",{expiresIn: "1d"});
                  res.cookie('token',token)
                  return res.json({status:"success"});
                  
               }
               else{
                  return res.json({Error:"incorrect password"})
               }
         })

      }else{
         return res.json({Error:"No email existing!!"})
      }

   });

 })



 //check session
 const verifyUser = (req, res,next)=>{
   const token = req.cookies.token;
   if(!token){
      return res.json({Error:"You are not authenticated"});
   }
   else{
      jwt.verify(token,"jwt-secret-key",(err, decoded)=>{
         if(err){
            return res.json({Error:"token is not correct"})
         }
         else{
            req.username = decoded.username;
            next();
         }
      })
   }
 }


 app.get('/',verifyUser,(req,res)=>{
   return res.json({status:"success",username:req.username});

 })

 //logout

 app.get('/logout',(req,res)=>{
   res.clearCookie('token');
   res.json({ status:"success"});
 })

 app.listen(8081,()=>{
    console.log("app listening to 8081"); 
    console.log("running")
 })