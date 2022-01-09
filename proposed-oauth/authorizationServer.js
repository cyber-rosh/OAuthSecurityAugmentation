var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var querystring = require('querystring');
var jose = require('jsrsasign');
var __ = require('underscore');
const json = require("body-parser/lib/types/json");
__.string = require('underscore.string');
var cors = require("cors");
const { forEach } = require("underscore");
const { type } = require("os");

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)



app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9003/authorize',
	tokenEndpoint: 'http://localhost:9003/token',
	iss: "ghost-auth-server",

};


// Auth_Server RSA keys.
var rsaKey = {
    "alg": "RS256",
    "d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "AuthServer"
  };

// function for repeating a string(str) n times.
var repeat = function(str, n){
	var out = ""
	for(x=0;x<=n;x++){
		out += str;
	}
	return out;
}

// ClientDB.
var clients = [
	{	
		client_id: "ghostinClientID", // client's unique identifier.
		client_secret: "ghostinClientSecret", // client's super secret.
		domain: "ghost-verification-server-domain", // verification servers' unique ID.
		ver_server_pub_key:	{
			"alg": "RS256",
			"e": "AQAB",
			"n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
			"kty": "RSA",
			"kid": "authserver"
		  }, // verification server's public key.
		redirect_uris: ["http://localhost:9000/callback"] // redirect_uris registered by the client.
	}

];




// global variable holding a list of all issued RAS pairs.
// elements of list will be an object, generated with createRSAPair() function.
var rsaIssued = [];

var tempRSAHolder = []; // temporary RSA holder 1.
var tempRSAHolder2 = []; // temporary RSA holder 2.


// function for generation of rsa pair,
// linked with the client_id and request_id.
var createRSAPair = function(client_id, request_id){
	return {
		request_id: request_id,
		client_id:client_id,
		private_key: rsaKey,
		public_key:{
			"alg": "RS256",
			"e": "AQAB",
			"n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
			"kty": "RSA",
			"kid": "authserver"
		  } 
	};
}

// function for pretty printing the incoming POST request.
var logPostRequest = (req) => {
	var log = console.log;

	log("\n",repeat("--",20),"INCOMING POST REQUEST",repeat("--", 20));
	log(`${req.method} ${req.path} HTTP/2.0`);
	forEach(req.headers, function (value, key) {
		log(`${key}: ${value}`);
	});

	log(`\n{"token":"${req.body.token}"}`);
	
}

// function for pretty printing the incoming GET request/
var logGetRequest = (req) =>{
	var l = console.log;

	l("\n",repeat("--",20),"INCOMING GET REQUEST",repeat("--", 20));
	l("\n")
	l(`${req.method} ${req.path}?${joinQueryParams(req.query)} HTTP/2.0`);
	forEach(req.headers, function (value, key) {
		l(`${key}: ${value}`);
	});
	l("\n");
	l(repeat("--", 50));

}

// function for joining query parameters.
var joinQueryParams = (paramsObject) =>{

	var output = [];
	var keys = __.keys(paramsObject);
	forEach(keys, function(value, index){
		var temp = `${value}=${paramsObject[value]}`;
		output.push(temp);
	});
	return output.join("&");

}

// createpairs route handler.
app.post("/createpairs" ,cors(),function(req, resp){

	resp["content-type"] =  "application/json";

	if(req.body){

		logPostRequest(req);
		var token = req.body.token;
		if(!token){
			console.log("\n[X] No Token Found In Request\n");
			resp.status(400).send({"response":"error"});
		}

		// extracting the payload of received JWT.
		console.log("",repeat("--", 20),"Decoded Token" ,repeat("--",20),"");
		var payload = getPayload(token);
		console.log("Decoded Token: ", payload);
		console.log(repeat("--", 50));
		console.log("\n\n\n");



		// fetching a valid client from the db.
		var client = __.find(clients, function(client){
			return client.client_id == payload.client_id;
		});

		// if a valid client is not found in the DB,
		// then log a message, send an error response.
		if(!client){
			console.log("no valid client found.");
			resp.status(400).send({response:"error"});
			return;
		}


		// checking whether the domain of verification server matches or not.
		if(payload.domain != client.domain){
			console.log({"error":"domain mismatched."});
			resp.status(400).send({response:"domain+missmatched."});
			return;
		}

		// if every check is passed then log good message.
		console.log("[!]\tValid client found.");
	
		var pubKey = jose.KEYUTIL.getKey(client.ver_server_pub_key); // fetching the pub_key of the VS 
		var isValid = jose.jws.JWS.verify(token, pubKey, ['RS256']); // verifying the JWT, with pub_key of VS

		if(isValid){
			
			console.log("[!]\tSingnature Verified..");
			console.log("[!]\tGenerating RSA key pair.");


			// creating rsa pairs, for the received request.
			var object = createRSAPair(payload.client_id, payload.request_id);
			
			console.log("[!]\tRSA pairs created..");
			// console.log(object);

			// storing both private and public key in the tempRSAHolder.
			tempRSAHolder.push(object); // adding the created RSA pair for a particular request to a global variable holding all the temporary issued RSAs.


			var header = { 'typ': 'JWT', 'alg': object.private_key.alg, 'kid': object.private_key.kid };
			var iden = payload.request_id;
			var payload = {
				request_id: iden,
				iss: authServer.iss,
				aud: payload.client_id,
				encrypt_priv_key: "<cipherTextHere>", // TODO: cipherText needed to be replaced with the object.private_key encrypted with the client_secret.
				iat: Math.floor(Date.now() / 1000),
			};
			
			// signing the JWT with auth_server's private key.
			var privateKey = jose.KEYUTIL.getKey(rsaKey);
			var respToken = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(payload), privateKey);

			resp.status(200).send({response:respToken});

		}else{
			console.log("bad signature.");
			resp.status(400).send({response:"bad signature."});
		}

	}else{
		resp.status(400).send({response:"request body is required."})
	}

});




app.get("/authorize", function(req, resp){


	console.log("\n", repeat("--", 50), "\n")

	/**
	 * 
	 * 	Route is expecting a token parameter.
	 * 	token is a jwt.
	 * 	Payload of token contains an encrypted field, a scopes field, issuer, time 
	 * 	of generation, and a request_id.
	 * 	
	 * 
	 */

	// extracting token from query.
	// /authenticate?token=<tokenHere>.
	var token = req.query.token;

	logGetRequest(req);

	if(!token){
		console.log({error:"no token present"});
		resp.status(400).send({"resp":"token required.."}).end();
		return;
	}
	// extracting payload from the token.
	var payload = getPayload(token);
	if(payload==""){
		resp.send({error:"invalid token."}).end();
		return;
	}

	// since each request is issued its own pairs of RSA,
	// here we are fetching the rsa for the received request_id, in the tempRSA.
	// The tempRSA db is used because the oauth request inititated by client may or may not be fully completed thus generated pairs have to be disposed off.
	var rsa_for_request = __.find(tempRSAHolder, function(rsa){
		return (payload.request_id == rsa.request_id);
	});


	// check whether if rsa_key_pairs are available for the request_id present in the tempRSAFolder or not.
	if(!rsa_for_request){
		console.log({error:"not a valid request"});
		resp.status(400).send({error:"not a valid request."}).end();
		return;
	}

	// since request_id is valid i.e its rsa_pairs are present in the tempRSAFolder. Here we are finding its index.
	var rsaIndex = tempRSAHolder.indexOf(rsa_for_request);  

	var pairs = tempRSAHolder[rsaIndex]; // pairs hold the object containing rsa_key_pair etc.

	if(rsaIndex > -1){
		// deleting the rsa entery for request_id so that it can't be replayed.
		tempRSAHolder.splice(rsaIndex, 1);
	}

	// console.log({object:pairs});

	// resp.send({msg:"work in progress"});


	// Here I have supposed that the user authentication is already performed,
	// and therefore redirecting the user to callback endpoint with the auth_token and other meta_data.

	if(pairs){
	
		var client = __.find(clients, function(client){
			return client.client_id == pairs.client_id
		});
		
		var auth_code = randomstring.generate(64); // generating auth_code
		pairs["auth_code"] = auth_code // adding auth_code to the pairs object.
		tempRSAHolder2.push(pairs);

		// console.log("Pairs with auth_code:\n",pairs);

		var encrypted_data = JSON.parse(payload.encrypted_data);
		
		resp.redirect(buildCallbackUri(client.redirect_uris[0],pairs.request_id, auth_code, encrypted_data.random_secret));

	}


});


app.post("/access-token", function(req, resp){

	
	resp["Content-type"] = "application/json";

	var req_token = req.body.token;


	var payload = getPayload(req_token);
	if(payload==""){
		resp.send({error:"invalid token."}).end();
	}
	
	// console.log(payload);

	var pairs = __.find(tempRSAHolder2, function(pair){
		return (payload.request_id == pair.request_id) && (payload.client_id == pair.client_id);
	});

	if(!pairs){
		resp.send({"error":"not a valid request."}).end();
		console.log({error:"no valid pair found"});
	}

	var pub_key = jose.KEYUTIL.getKey(pairs.public_key);
	var isValid = jose.jws.JWS.verify(req_token, pub_key, ["RS256"]);
	if(isValid){
		
		console.log("\n\t[!] Creating access_token\n");

		var i = tempRSAHolder2.indexOf(pairs); // finding the index of pairs in tempRSAHolder2.
		if(i>-1){
			tempRSAHolder2.splice(i, 1) // removing the index 
		}


		var access_token = randomstring.generate(128);
		pairs["access_token"] = access_token;

		rsaIssued.push(pairs); // pushing pairs to a permanent list.
		// console.log(rsaIssued);

		var client_pub_key = Buffer.from(JSON.stringify(pairs.public_key)).toString("base64");

		var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid };
		var payload = {
			access_token:access_token,
			iat:Math.floor(Date.now() / 1000),
			exp:Math.floor(Date.now() / 1000) + (1*60*60*24*7),
			client_pub_key:client_pub_key

		}

		var priv_key = jose.KEYUTIL.getKey(rsaKey);
		var token = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(payload), priv_key);
		
		console.log("",repeat("--", 20),"ACCESS_TOKEN_CREATED",repeat("--",20), "\n")
		console.log(token,"\n");
		console.log(getPayload(token))

		console.log(repeat("--",50))

		resp.send({token:token}).end();



	}else{
		resp.send({msg:"signature not valid."}).end();
	}


});





// function for building the callback uri containing JWT which is sent to the client through redirection.
function buildCallbackUri(redirect_uri, req_id, auth_code, random_secret){


	var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid };

	// TODO: need to encrypt this object with the random_secret.
	var encrypted_data = {
		request_id: req_id,
		auth_code:auth_code
	};

	var payload = {
		iss:"auth_server",
		iat:Math.floor(Date.now() / 1000),
		aud:"client",
		encrypted_data: JSON.stringify(encrypted_data) // TODO: need to encrypt the data with the random_secret.
	};

	var privKey = jose.KEYUTIL.getKey(rsaKey);
	var token = jose.jws.JWS.sign(header.alg,JSON.stringify(header), JSON.stringify(payload) ,privKey);


	return redirect_uri+`?token=${token}`;

}




// function returns the payload part of JWT.
// returned part is decoded from base64 and is json parsed.
function getPayload(token) {
	try{
	var temp = token.split(".");
	var t = new Buffer(temp[1], "base64");
	// console.log(t.toString("ascii"));
	return JSON.parse(t.toString());
	}catch(err){
		console.log({error:"not a valid token."});
		return "";
	}
}


app.use('/', express.static('files/authorizationServer'));
app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

var server = app.listen(9003, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('Authorization Server is listening at http://%s:%s', host, port);
});
 
