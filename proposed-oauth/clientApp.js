var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var jose = require('jsrsasign');
var base64url = require('base64url');
var __ = require('underscore');
const { response } = require("express");
const json = require("body-parser/lib/types/json");
const { forEach } = require("underscore");
const replaceAll = require("underscore.string/replaceAll");
__.string = require('underscore.string');


var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9003/authorize',
	tokenEndpoint: 'http://localhost:9003/access-token'
};


var rsaPrivateKey = {
    "alg": "RS256",
    "d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "verificationserver"
  };

var rsaPublicKey = {
	"alg": "RS256",
	"e": "AQAB",
	"n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
	"kty": "RSA",
	"kid": "authserver"
  };


// client information
var client = {
	"client_id": "ghostinClientID",
	"client_secret": "ghostinClientSecret",
	"redirect_uris": ["http://localhost:9000/callback"],
	"scope": "visits membershipTime averageTimeSpentInLibrary"
};


var access_token = null;
var scope = client.scope;




var verificationServer = {
	verify:"http://localhost:9009/verify"
}

// function for repeating a string(str) n times.
var repeat = function(str, n){
	var out = ""
	for(x=0;x<=n;x++){
		out += str;
	}
	return out;
}


app.get('/', function (req, res) {

	res.render('index', {access_token: access_token, scope: scope});
});

app.get('/oauth', function(req, res){
	

	// making request to verification server for verification and generating a rsa pair for the current client request.
	// making a post request to verification server,
	// for verification of the client, if it is verified, 
	// a valid token is returned, otherwise error is returned and request is canceled.

	var url = verificationServer.verify+`?client_id=${client.client_id}`;

	var headers = {"content-type":"application/json"};
	var body = JSON.stringify({
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		meta: "<clientSpecificMetaDataForVerifciationServer>"
	});

	var verResponse = request("POST", url, {
		headers:headers,
		body:body
	});

	// parsing the received response.
	var parsedResp = JSON.parse(verResponse.body.toString("ascii"));


	console.log(repeat("--", 20), "Token From Auth Server After Verification" ,repeat("--", 20));
	console.log("\n\n",parsedResp);
	var payload = getPayload(parsedResp.token); // extracting the payload of the token.
	console.log("\n\n", payload);
	console.log(repeat("--", 50));


	// res.status(verResponse.statusCode).send(parsedResp);
	var auth_uri = buildAuthURI(authServer.authorizationEndpoint,payload.request_id, client.scope);


	console.log("\n\n",repeat("--",20),"AUTH URI START", repeat("--", 20), "\n");
	console.log(auth_uri);
	console.log("\n\n");
	var token_payload = getPayload(auth_uri.split("=")[1]);
	console.log(token_payload);
	console.log(repeat("--", 50));


	// res.send({"auth_uri":auth_uri});

	res.redirect(auth_uri);
});



app.get("/callback", function(req, resp){


	console.log("\n\n\n",repeat("--",20),"Callback", repeat("--", 20));
	var token = req.query.token
	if(!token){
		console.log("no token present..");
	}

	logGetRequest(req);

	console.log("\n\n",repeat("--",20),"Callback END", repeat("--", 20));

	var token_payload = getPayload(token);

	var encrypted_data = JSON.parse(token_payload.encrypted_data);

	var headers = {"typ":"JWT", 'alg':"RS256", "kid":"client"};
	var payload = {
		iss:client.client_id,
		iat:Math.floor(Date.now()/1000),
		request_id:encrypted_data.request_id,
		auth_code:encrypted_data.auth_code,
		client_id: client.client_id,
	};
	var privateKey = jose.KEYUTIL.getKey(rsaPrivateKey);
	var token = jose.jws.JWS.sign(headers.alg, JSON.stringify(headers), JSON.stringify(payload), privateKey);
	var req_headers = {
		"Content-type":"application/json"
	};

	var body = {
		token:token
	};

	var acces_token = request("POST", authServer.tokenEndpoint, {
		headers:req_headers,
		body:JSON.stringify(body)
	});

	console.log("\n\n", repeat("--", 20), "Got Access Token", repeat("--", 20))
	console.log(acces_token.body.toString("ascii"));
	console.log("\n\n")
	console.log(getPayload(acces_token.body.toString("ascii")));
	console.log("\n\n", repeat("--", 20), "Access Token END", repeat("--", 20))


	var parsedObject = JSON.parse(acces_token.body.toString("ascii"));
	access_token = parsedObject.token; 
	resp.redirect("/");

});



app.get("/libraryStats", function(req, resp){


	if(access_token==null){
		resp.redirect("/oauth");
	}

	var resourceLink = "http://localhost:9002/libraryStats"

	var scope = client.scope;


	var header = { 'typ': 'JWT', 'alg': "RS256", 'kid': "authserver" };
	var payload = {
		iss:client.client_id,
		aud:"resourceServer",
		iat:Math.floor(Date.now()/1000),
		exp:Math.floor(Date.now() / 1000) + (1*60),
		inner_token:access_token,
		scope:scope
	}

	var privKey = jose.KEYUTIL.getKey(rsaPrivateKey);
	var mainToken = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(payload), privKey);

	var response = request("GET", resourceLink+`?main_token=${mainToken}`,{
		header:{'content-type':"application/x-www-form-urlencoded"}
	});
	var body = JSON.parse(response.getBody());
	// console.log(response.body.toString("ascii"));

	// if there is error in response, then token is expired.
	// therefore redirecting to oauth for getting new token.
	if(body.error){
		return resp.redirect("/oauth");
	}

	return resp.render("libraryStats",{scope:scope, data:body});

});




// function for logging GET request.
var logGetRequest = (req) =>{
	var l = console.log;

	l(`${req.method} ${req.path}?token=${req.query.token} HTTP/2.0`);
	forEach(req.headers, function (value, key) {
		l(`${key}: ${value}`);
	});
	l("\n");

	var token_payload = getPayload(req.query.token);
	l(token_payload);


}



// function for building  auth uri.
var buildAuthURI = function(url, request_id, scopes){


	var headers = {"typ":"JWT", 'alg':"RS256", "kid":"client"};

	// TODO: below object is required to be encrypted with the public key of authorization_server.
	var encrypted_data = {
		client_id:client.client_id,
		random_secret: randomstring.generate(64)
	};

	var payload = {
		iss:"ghostClient",
		request_id: request_id, 
		scopes: scopes,
		encrypted_data: JSON.stringify(encrypted_data),
		iat:Math.floor(Date.now()/1000)
	};

	var privateKey = jose.KEYUTIL.getKey(rsaPrivateKey);
	var signedToken = jose.jws.JWS.sign(headers.alg, JSON.stringify(headers), JSON.stringify(payload), privateKey);
	url += `?token=${signedToken}`;

	return url; 
}

// function returns the payload part of JWT.
// returned part is decoded from base64 and is json parsed.
function getPayload(token) {
	var temp = token.split(".");
	var t = new Buffer(temp[1], "base64");
	// console.log(t.toString("ascii"));
	return JSON.parse(t.toString());
}





app.use('/', express.static('files/client'));


var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
