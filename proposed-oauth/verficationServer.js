var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var jose = require('jsrsasign');
var __ = require('underscore');
var request = require("sync-request");
const { query, response } = require("express");
var qs = require("qs");
const { forEach, random } = require("underscore");
const randomstring = require("randomstring");
const json = require("body-parser/lib/types/json");
const { RSA_PKCS1_OAEP_PADDING } = require("constants");
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); 
app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/verificationServer');
app.set('json spaces', 4);

// rsa keys.
var rsaKey = {
    "alg": "RS256",
    "d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "verificationserver"
  };


// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9003/authorize',
	tokenEndpoint: 'http://localhost:9003/token',
    pairEndpoint: "http://localhost:9003/createpairs",
    authenEndpoint: "http://localhost:9003/authenticate"
};



// Verification server details.
var verficationServer = {
    domain: "ghost-verification-server-domain",
    iss:"verificationServer",
    aud:"authorizationServer",

};

//  clients available in the verification server.
var clients =  [
    {
    "client_id":"ghostinClientID"
    }
]


// function for repeating a string(str) n times.
var repeat = function(str, n){
	var out = ""
	for(x=0;x<=n;x++){
		out += str;
	}
	return out;
}



app.post("/verify",function(req, resp){

    /**
     *  
     *  When the verification server receives the request for oauth ,
     *  It will first verify the client, then it will make a post request to auth_server for the generation of RSA Key Pair, but in response only Private Key will be present in cipher form, which will be inside a signed jwt. on receiving the response it will forward back the same response to the client app.
     * 
     * 
     */

    // setting response header to be a json.
    resp["content-type"] = "application/json";


    // this route is acceping a single query parameter.
    // /oauth?client_id=<yourClientID>


    // request body is always json object.
    var body = req.body;


    if(!body){
        resp.status(400).send({"error":"not a valid request"});
    }


    var client = __.find(clients, function(c){
        return c.client_id == body.client_id;
    });

    if(!client){
        resp.status(400).send({"error":"not a valid client."});
    }

    console.log("\n\n[!!] Client Found & Verified: ", client);


    var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid };

    var iden = randomstring.generate(16);
    var payload = {
        iss: verficationServer.iss,
        aud:verficationServer.aud,
        request_id: iden,
        domain: verficationServer.domain,
        client_id: client.client_id,
        iat: Math.floor(Date.now() / 1000),
    };

    var privateKey = jose.KEYUTIL.getKey(rsaKey);
    var request_token = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(payload), privateKey);


    // post body
    var body = JSON.stringify({"token":request_token});
    var headers = {'Content-Type': 'application/json'};

    console.log("\nMaking POST request for generating a RSA pair\n"); 
 

    var ticketResp = request("POST", authServer.pairEndpoint, {
        body:body, 
        headers:headers
    })

    // parsing the response to a json object.
    var parsedResponse = JSON.parse(ticketResp.body.toString("ascii"));
    
    var logResponse = function(response){
        console.log( repeat("--", 20),"RESPONSE", repeat("--",20));
        console.log(`${ticketResp.statusCode} HTTP/2.0`);
        forEach(ticketResp.headers, function(value, key){
            console.log(`${key}: ${value}`);
        });
        console.log(`\n{"response":"${parsedResponse.response}"}`);
        console.log("\n\nDecoded: ", getPayload(parsedResponse.response));
        console.log("\n",repeat("--",20) ,"RESPONSE", repeat("--",20));
    }

    logResponse(ticketResp);

    if(ticketResp.statusCode >= 200 & ticketResp.statusCode <= 300){
        resp.json({"token":parsedResponse.response});
    }else{
        resp.status(ticketResp.statusCode).send(parsedResponse);
    }


    return;    

});


// function returns the payload part of JWT.
// returned part is decoded from base64 and is json parsed.
function getPayload(token) {
	var temp = token.split(".");
	var t = new Buffer(temp[1], "base64");
	// console.log(t.toString("ascii"));
	return JSON.parse(t.toString());
}




var server = app.listen(9009, "localhost", function(){

    var host = server.address().address;
    var port = server.address().port;
    console.log(`Verification Server listening on: http://${host}:${port}`);

});
