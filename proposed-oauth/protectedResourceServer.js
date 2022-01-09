var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var __ = require('underscore');
var cors = require('cors');
var jose = require('jsrsasign');
var base64url = require('base64url');
const replaceAll = require("underscore.string/replaceAll");

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
    "name" : "Open Library",
    "description" : "Open Library API"
}

var authServerPublicKeyObject = {
    "alg": "RS256",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "authserver"
  };



// Function returns the payload part of JWT.
// returned part is decoded from base64 and is json parsed.
function getPayload(token) {
	try{
	var temp = token.split(".");
	var t = new Buffer(temp[1], "base64");
	// console.log(t.toString("ascii"));
	return JSON.parse(t.toString());
	}catch(err){
		console.log({error:"not a valid token."});
		return {};
	}
}


// function for repeating a string(str) n times.
var repeat = function(str, n){
	var out = ""
	for(x=0;x<=n;x++){
		out += str;
	}
	return out;
}

app.get("/libraryStats",function(req, res) {
    var mainToken = null;
    var auth = req.headers['authorization'];
    if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
        mainToken = auth.slice('bearer '.length);
    } else if (req.body && req.body.main_token) {
        mainToken = req.body.main_token;
    } else if (req.query && req.query.main_token) {
        mainToken = req.query.main_token;
    }
    
    console.log("\n",repeat("--", 20), "Token Received" ,repeat("--", 20));
    console.log('\nIncoming token: %s\n\n', mainToken);

	var authPubKey = jose.KEYUTIL.getKey(authServerPublicKeyObject);
    
    var mainTokenPayload = getPayload(mainToken);
    console.log("\n")
    console.log(mainTokenPayload);
    console.log("\n");
    

    var innerToken = mainTokenPayload.inner_token;

    console.log(repeat("--",20),"Inner_Token", repeat("--",20));
    console.log(getPayload(innerToken));
    console.log("\n")
    console.log(repeat("--", 50));

    var isValidInner = jose.jws.JWS.verify(innerToken, authPubKey, ['RS256']);
    
	if (isValidInner) {

		console.log('\n\n\t[!] Inner token\'s signature is valid.');

        var payload = getPayload(innerToken);
        var clientPubKeyObj = JSON.parse(Buffer.from(payload.client_pub_key, "base64").toString("ascii"));     
        var clientPubKey = jose.KEYUTIL.getKey(clientPubKeyObj);
        
        var isValidMainToken = jose.jws.JWS.verify(mainToken, clientPubKey, ["RS256"]);

        if(isValidMainToken){   
            console.log("\t[!] Main token's signature is valid.");

            req.access_token = innerToken.access_token;
            req.scope = mainTokenPayload.scope.split(" ");
            

            if(isExpiredToken(innerToken) || isExpiredToken(mainToken)){
                console.log("\t[X] Token expired..");
                res.json({"error":"token expired"});
            }

            var libraryStats = {};
            if (__.contains(req.scope, 'visits')) {
                libraryStats.visits = 120;
            }

            if (__.contains(req.scope, 'membershipTime')) {
                libraryStats.membershipTime = 2;
            }

            if (__.contains(req.scope, 'averageTimeSpentInLibrary')) {
                libraryStats.averageTimeSpentInLibrary = 4.5;
            }

            console.log('\nSending libraryStats: ', libraryStats);

            res.json(libraryStats);	

        }	
    }


	
});

// function for checking token's expiry validity.
// returns true if the token is expired.
var isExpiredToken = function(token){
    var now = Math.floor(Date.now()/1000);
    return now > token.exp;
}



var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('Resource Server is listening at http://%s:%s', host, port);
});
