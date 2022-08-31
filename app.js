/*
 */
var http = require('http');
var express = require('express');
var path = require('path');
var bodyparser = require('body-parser');
var mongoose = require('mongoose');
var mongoSanitize = require('express-mongo-sanitize');
var Message = require('./schema/Message');

var app = express();

mongoose.connect('mongodb://localhost:27017/chatapp',
  function(err){
    if(err){
      console.error(err);
    }
    else{
      console.log("Successfully connected to MongoDB.");
    }
  }
);

app.use(bodyparser());

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.get("/", function(req, res, next){
  Message.find({}, function(err, msgs){
    if(err) throw err;
    return res.render('index', {messages: msgs});
  });
});

app.get("/update", function(req, res, next){
  return res.render('update');
});

app.post("/update", function(req, res, next){
  var newMessage = new Message({
    username: req.body.username,
    message: req.body.message
  });
  newMessage.save((err)=>{
    if(err) throw err;
    return res.redirect("/");
  });  
});

app.get("/match", function(req, res, next){
  return res.render('match');
});

app.post("/match", function(req, res, next){
  console.log(req.body.username);
  const usern = req.body.username;
  const user_ = {"$ne": null}; 
  console.log(user_);
  query = Message.find({username:usern});
  query.select('username, message');
  query.exec((err, msgs)=>{
	if(err) return HandleError(err); 
    	return res.render('index', {messages: msgs});
  });
});

app.get("/search/:name", function(req, res, next){
  console.log(req.params.username);
  // var name = mongoSanitize.sanitize(req.params.name); 
  var username = req.params.name; //NoSQL Injection #63
  // var query1 = {username:req.params.name};
  Message.find({username:username}, function(err, msgs){
    if(err) throw err;
    return res.render('index', {messages: msgs});
  });
});

var server = http.createServer(app);
server.listen('5000');
