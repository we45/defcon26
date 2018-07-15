# Cut The Funds App
## Threat Model for: Cut The Funds App
### Process Flow Diagram
![Flow Diagram](/Users/abhaybhargav/Documents/Code/Python/defcon26/tp/ctf/results/diagram.svg)
## Threat Models
### Functionality: manage_expenses
As a regular user of the application I would like to create and delete/manage expenses incurred by me during the course of business travel so I can get reimbursed/approved for it
#### Abuse Cases

##### As a curious employee I would like to see the expenses incurred by my bosses especially the CEO and Senior Management and leak that to the press
**Attacker attempts to steal Auth Token from user with malicious client-side script. Target is any front-end using the API, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| check for persistent XSS with Automated Tools | Automated Test | zap,burp,arachni |
| check for manual XSS persistent | Manual Test | zap,burp,arachni |
**External attacker may be able to bypass user authentication by compromising weak passwords of users, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Default passwords for ZAP Fuzzer | Automated Test | nmap,zap,burp,arachni |
| Check for weak passwords for ZAP Fuzzer | Automated Test | zap,burp,arachni |
**Attacker may be able to gain access to user accounts by successfully performing Injection Attacks/RCE driven attacks, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for OS Command Injection/Eval Injection with Automated Tools | Automated Test | burp,tplmap |
| Check for Template Injection with Automated Tools | Automated Test | burp,tplmap |
| Use Automated Vulnerability Scanners to test for SQL Injection | Automated Test | zap,burp,arachni |
| Attempt to force generic Error Messages, especially 500 Errors | Automated Test | zap,burp,arachni |
**Attacker attempts to use authenticated access and expenseID to gain access to other expenses by reference by ID, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| check for IDOR Manually | Manual Test | manual |
**Attacker attempts to compromise auth token by gaining access to the end user's auth token by performing Man in the Middle Attacks, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| tests against SSL with SSLLabs.com, Burp and Zap | Automated Test | burp,zap,ssllab |


##### As a malicious coworker I would takeover a colleague's access to the Expense System so I could raise bogus expenses and get my colleague fired for fraud
**Attacker attempts to steal Auth Token from user with malicious client-side script. Target is any front-end using the API, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| check for persistent XSS with Automated Tools | Automated Test | zap,burp,arachni |
| check for manual XSS persistent | Manual Test | zap,burp,arachni |
**External attacker may be able to bypass user authentication by compromising weak passwords of users, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Default passwords for ZAP Fuzzer | Automated Test | nmap,zap,burp,arachni |
| Check for weak passwords for ZAP Fuzzer | Automated Test | zap,burp,arachni |
**Attacker may be able to gain access to user accounts by successfully performing Injection Attacks/RCE driven attacks, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for OS Command Injection/Eval Injection with Automated Tools | Automated Test | burp,tplmap |
| Check for Template Injection with Automated Tools | Automated Test | burp,tplmap |
| Use Automated Vulnerability Scanners to test for SQL Injection | Automated Test | zap,burp,arachni |
| Attempt to force generic Error Messages, especially 500 Errors | Automated Test | zap,burp,arachni |
**Attacker attempts to use authenticated access and expenseID to gain access to other expenses by reference by ID, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| check for IDOR Manually | Manual Test | manual |
**Attacker attempts to compromise auth token by gaining access to the end user's auth token by performing Man in the Middle Attacks, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| tests against SSL with SSLLabs.com, Burp and Zap | Automated Test | burp,zap,ssllab |
**Attacker attempts to compromise auth token by gaining access to the end user's auth token by performing Man in the Middle Attacks, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| tests against SSL with SSLLabs.com, Burp and Zap | Automated Test | burp,zap,ssllab |
**Attacker may be able to gain access to user accounts by successfully performing Injection Attacks/RCE driven attacks, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for OS Command Injection/Eval Injection with Automated Tools | Automated Test | burp,tplmap |
| Check for Template Injection with Automated Tools | Automated Test | burp,tplmap |
| Use Automated Vulnerability Scanners to test for SQL Injection | Automated Test | zap,burp,arachni |
| Attempt to force generic Error Messages, especially 500 Errors | Automated Test | zap,burp,arachni |
**External attacker may be able to bypass user authentication by compromising weak passwords of users, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Default passwords for ZAP Fuzzer | Automated Test | nmap,zap,burp,arachni |
| Check for weak passwords for ZAP Fuzzer | Automated Test | zap,burp,arachni |
**External attacker may be able to bypass user authentication by compromising default passwords of users, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Default passwords for ZAP Fuzzer | Automated Test | nmap,zap,burp,arachni |
**Attacker attempts to tamper with parameters related to the Authentication process to bypass authentication and gain access as a user of the application, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| test for authentication bypass performed manually | Manual Test | manual |
| check for Directory Listing with Automated Tools | Automated Test | burp,zap,arachni |
**Attacker attempts to steal Auth Token from user with malicious client-side script. Target is any front-end using the API, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| check for persistent XSS with Automated Tools | Automated Test | zap,burp,arachni |
| check for manual XSS persistent | Manual Test | zap,burp,arachni |



### Functionality: approve_expense
As a manager I would review and approve expenses of colleagues based on evidence of them incurring the expense
#### Abuse Cases

##### As a malicious employee I would get my own expenses approved so I can pass bogus expenses as genuine expenditure
**Attacker attempts to steal Auth Token from user with malicious client-side script. Target is any front-end using the API, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| check for persistent XSS with Automated Tools | Automated Test | zap,burp,arachni |
| check for manual XSS persistent | Manual Test | zap,burp,arachni |
**Attacker attempts to compromise auth token by gaining access to the end user's auth token by performing Man in the Middle Attacks, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| tests against SSL with SSLLabs.com, Burp and Zap | Automated Test | burp,zap,ssllab |
**Attacker may be able to bypass user authentication by compromising weak passwords of manager, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Default passwords for ZAP Fuzzer | Automated Test | nmap,zap,burp,arachni |
| Check for weak passwords for ZAP Fuzzer | Automated Test | zap,burp,arachni |
**Attacker may be able to tamper with expense information by successfully performing Injection Attacks/RCE driven attacks against some of the unauthenticated API Endpoints in the application, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for OS Command Injection/Eval Injection with Automated Tools | Automated Test | burp,tplmap |
| Check for Template Injection with Automated Tools | Automated Test | burp,tplmap |
| Use Automated Vulnerability Scanners to test for SQL Injection | Automated Test | zap,burp,arachni |
| Attempt to force generic Error Messages, especially 500 Errors | Automated Test | zap,burp,arachni |
**Attacker attempts to bypass approval controls through IDOR like attacks and approve expenses as a manager performing Privilege Escalation, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| attempt to tamper with params and manipulate JSON payloads with Mass Assignment | Manual Test | manual |



### Functionality: login_user
As an employee of the organization,
I would like to login to the Cut the Funds App to manage my expenses and reimbursements

#### Abuse Cases

##### As an external attacker, I would compromise a single/multiple user accounts to gain access to sensitive customer information
**Attacker attempts to steal Auth Token from user with malicious client-side script. Target is any front-end using the API, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| check for persistent XSS with Automated Tools | Automated Test | zap,burp,arachni |
| check for manual XSS persistent | Manual Test | zap,burp,arachni |
**External attacker may be able to bypass user authentication by compromising weak passwords of users, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Default passwords for ZAP Fuzzer | Automated Test | nmap,zap,burp,arachni |
| Check for weak passwords for ZAP Fuzzer | Automated Test | zap,burp,arachni |
**Attacker attempts to compromise auth token by gaining access to the end user's auth token by performing Man in the Middle Attacks, Severity: Medium**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| tests against SSL with SSLLabs.com, Burp and Zap | Automated Test | burp,zap,ssllab |
**Attacker may be able to gain access to user accounts by successfully performing Injection Attacks/RCE driven attacks, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for OS Command Injection/Eval Injection with Automated Tools | Automated Test | burp,tplmap |
| Check for Template Injection with Automated Tools | Automated Test | burp,tplmap |
| Use Automated Vulnerability Scanners to test for SQL Injection | Automated Test | zap,burp,arachni |
| Attempt to force generic Error Messages, especially 500 Errors | Automated Test | zap,burp,arachni |
**Attacker attempts to tamper with parameters related to the Authentication process to bypass authentication and gain access as a user of the application, Severity: High**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| test for authentication bypass performed manually | Manual Test | manual |
| check for Directory Listing with Automated Tools | Automated Test | burp,zap,arachni |



## Vulnerabilities

### Weak Hash used - MD5
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
MD5 is a a weak hash which is known to have collision. Use a strong hashing function.
### Evidences

#### URL/File/Ref: mongocr.js
#### Raw Input
```

            var md5 = crypto.createHash('md5');
            // Generate keys used for authentication
            md5.update(username + ':mongo:' + password, 'utf8');
            var hash_password = md5.digest('hex');
            // Final key
            md5 = crypto.createHash('md5');
            md5.update(nonce + username + hash_password, 'utf8');
            key = md5.digest('hex');
            }
```
### Deserialization Remote Code Injection
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
User controlled data in 'unserialize()' or 'deserialize()' function can result in Object Injection or Remote Code Injection.
### Evidences

#### URL/File/Ref: project.controller.js
#### Raw Input
```

module.exports.serializeMe = (req, res) => {
        try {
            let expObj = req.body.expenseObject;
            let payload = base64.decode(expObj).toString();
            serialize.unserialize(payload);
            // console.log(unser);
            res.status(200).json({
                success: "suxus"
            });
        } catch (err) {
            res.status(400).json({
                error: err
            });
```
### Password Hardcoded
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
A hardcoded password in plain text was identified.
### Evidences

#### URL/File/Ref: user.json
#### Raw Input
```

{
    "_id": {
        "$oid": "5a9e798cc5bf9372b05b7cfd"
    },
    "email": "abhay@we45.com",
    "firstName": "Abhay",
    "lastName": "Bhargav",
    "password": "5e838bd134fd95129716cf8f01294a481e2775d2f9b3a7a4438ba9c80b8d556a",
    "isSuperAdmin": true,
    "createdOn": {
        "$date": "2018-03-06T11:20:44.037+0000"
    },
    "cards": [],
    "__v": 0
} {
    "_id": {
        "$oid": "5ace0a57b10d64111c00adad"
    },
    "firstName": "Maya",
    "lastName": "Williams",
    "email": "maya.williams@widget.co",
    "password": "f90b416a4957033458a82450ef141a2d4167a744afdcb2c1ca94998605993c2d",
    "userType": "user",
    "createdOn": {
        "$date": "2018-04-11T13:15:03.056+0000"
    },
    "isSuperAdmin": false,
    "cards": ["980fccc5f252848498c130f4c4bbe1b8829a75414dc9ed2a71f272f81b0d85fb"],
    "__v": 0
} {
    "_id": {
        "$oid": "5ace0a57b10d64111c00adae"
    },
    "firstName": "Dave",
    "lastName": "Matthews",
    "email": "dave.matthews@widget.co",
    "password": "f90b416a4957033458a82450ef141a2d4167a744afdcb2c1ca94998605993c2d",
    "userType": "user",
    "createdOn": {
        "$date": "2018-04-11T13:15:03.070+0000"
    },
    "isSuperAdmin": false,
    "cards": ["71f69aa44c92f04ea6ca36df2512aa30829a75414dc9ed2a71f272f81b0d85fb"],
    "__v": 0
} {
    "_id": {
        "$oid": "5ace0a57b10d64111c00adaf"
    },
    "firstName": "Amy",
    "lastName": "Cho",
    "email": "amy.cho@widget.co",
    "password": "114d4a747a1091ae0aebb2188185a35b2fbb802e96e78aaa00b7a1091ba758d2",
    "userType": "user",
    "createdOn": {
        "$date": "2018-04-11T13:15:03.082+0000"
    },
    "isSuperAdmin": false,
    "cards": ["980fccc5f252848498c130f4c4bbe1b8829a75414dc9ed2a71f272f81b0d85fb"],
    "__v": 0
} {
    "_id": {
        "$oid": "5ace0a57b10d64111c00adb0"
    },
    "firstName": "Andy",
    "lastName": "Roberts",
    "email": "andy.roberts@widget.co",
    "password": "dbd797407450e3798bf77e4dec893c754a9601b5587a35952577ee2b4efb3840",
    "userType": "manager",
    "createdOn": {
        "$date": "2018-04-11T13:15:03.094+0000"
    },
    "isSuperAdmin": false,
    "cards": [],
    "__v": 0
}
```
### XSS - Reflected Cross Site Scripting
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
Untrusted User Input in Response will result in Reflected Cross Site Scripting Vulnerability
### Evidences

#### URL/File/Ref: body-events.js
#### Raw Input
```

app2 = express();
app2.use(bodyParser.json());
app2.use(cors({
    origin: dynamicOrigin
}));
app2.post('/', function(req, res) {
    res.send(req.body);
});

/* -------------------------------------------------------------------------- */
```
### Weak Hash used - SHA1
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
SHA1 is a a weak hash which is known to have collision. Use a strong hashing function.
### Evidences

#### URL/File/Ref: index.js
#### Raw Input
```

    return '"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk"'
    }

    // compute hash of entity
    var hash = crypto
        .createHash('sha1')
        .update(entity, 'utf8')
        .digest('base64')
        .substring(0, 27)
```
### Loading of untrusted YAML can cause Remote Code Injection
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
User controlled data in 'load()' function can result in Remote Code Injection.
### Evidences

#### URL/File/Ref: expense.controller.js
#### Raw Input
```

        // if (validObject) {
        let yamlExpense = req.files.yamlExpense;
        let ybuf = yamlExpense.data;
        let ystring = ybuf.toString();

        let y = yaml.load(ystring);
        console.log("Hello".toString());
        res.status(200).json(y);
        log.info(req);
        log.info(res);
```
### Secret Hardcoded
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
A hardcoded secret was identified.
### Evidences

#### URL/File/Ref: config.dev.js
#### Raw Input
```

const mysql_database = process.env.MYSQL_DATABASE || 'expenses';
const upload_dir = '../uploads';

module.exports = {
        'mongoUri': "mongodb://" + mongo_ip + ":27017/cut_the_funds",
        'secret': "aec12a48-720c-4102-b6e1-d0d873627899",
        'salt': 'secretSalt',
        'userPerms': ["view_project", "create_expense", "delete_expense", "view_expense", "modify_expense", "view_coupons", "create_card"],
        'mgrPerms': ["create_project", "delete_project", "modify_project", "view_expense", "approve_expense", "view_project"],
        "uploadDir": upload_dir,
```
### Express BodyParser Tempfile Creation Issue
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
POST Request to Express Body Parser 'bodyParser()' can create Temporary files and consume space.
### Evidences

#### URL/File/Ref: request.js
#### Raw Input
```

 *-Checks body params, ex: id = 12, {
         "id": 12
     }
     *-Checks query string params, ex: ? id = 12 *
     *
     To utilize request bodies, `req.body` *
     should be an object.This can be done by using *
     the `bodyParser()`
 middleware.*
     *
     @param {
         String
     }
 name
     *
     @param {
         Mixed
     }[defaultValue] *
     @return {
         String
     }
```
### SQLi - SQL Injection
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
Untrusted User Input in RAW SQL Query can cause SQL Injection
### Evidences

#### URL/File/Ref: project.controller.js
#### Raw Input
```

        console.log(tokenHeader);
        let validObject = await auth.validateManager(tokenHeader, "create_project");
        console.log(validObject);
        if (validObject.tokenValid && validObject.roleValid) {
            console.log(validObject);
            let dynamicQuery = "SELECT country, currency_code from currency WHERE country = '" + req.body.search + "'";
            console.log(dynamicQuery);
            connection.query(dynamicQuery, function(error, results, fields) {
                        if (error) {
                            log.error(error)
```
### Unescaped variable in EJS template file
CWE: None, Severity: Medium, Tool: NodeJsScan

#### Description
The EJS template has an unescaped variable. Untrusted user input passed to this variable results in Cross Site Scripting (XSS).
### Evidences

#### URL/File/Ref: template.js
#### Raw Input
```

 *
 var compiled = _.template('<%= "\\<%- value %\\>" %>');
 * compiled({
     'value': 'ignored'
 });
 * // => '<%- value %>'
 *
 * // Use the `imports` option to import `jQuery` as `jq`.
 *
 var text = '<% jq.each(users, function(user) { %><li><%- user %></li><% }); %>';
 *
 var compiled = _.template(text, {
     'imports': {
         'jq': jQuery
     }
 });
 * compiled({
     'users': ['fred', 'barney']
 });
 * // => '<li>fred</li><li>barney</li>'
 *
```
### Code Execution through IIFE
CWE: 502, Severity: High, Tool: Npm Audit

#### Description
Affected versions of `node-serialize` can be abused to execute arbitrary code via an [immediately invoked function expression](https://en.wikipedia.org/wiki/Immediately-invoked_function_expression) (IIFE) if untrusted user input is passed into `unserialize()`.
#### Remediation
There is no direct patch for this issue. The package author has reviewed this advisory, and provided the following recommendation:

```
To avoid the security issues, at least one of the following methods should be taken:

1. Make sure to send serialized strings internally, isolating them from potential hackers. For example, only sending the strings from backend to fronend and always using HTTPS instead of HTTP.

2. Introduce public-key cryptosystems (e.g. RSA) to ensure the strings not being tampered with.
```
### Evidences

### Out-of-bounds Read
CWE: 125, Severity: Medium, Tool: Npm Audit

#### Description
Versions of `base64url` before 3.0.0 are vulnerable to to out-of-bounds reads as it allocates uninitialized Buffers when number is passed in input on Node.js 4.x and below.
#### Remediation
Update to version 3.0.0 or later.
### Evidences

### Regular Expression Denial of Service
CWE: 400, Severity: Low, Tool: Npm Audit

#### Description
Versions of `uglify-js` prior to 2.6.0 are affected by a regular expression denial of service vulnerability when malicious inputs are passed into the `parse()` method.


### Proof of Concept

```
var u = require('uglify-js');
var genstr = function (len, chr) {
    var result = "";
    for (i=0; i<=len; i++) {
        result = result + chr;
    }

    return result;
}

u.parse("var a = " + genstr(process.argv[2], "1") + ".1ee7;");
```

### Results
```
$ time node test.js 10000
real	0m1.091s
user	0m1.047s
sys	0m0.039s

$ time node test.js 80000
real	0m6.486s
user	0m6.229s
sys	0m0.094s
```
#### Remediation
Update to version 2.6.0 or later.
### Evidences

### Incorrect Handling of Non-Boolean Comparisons During Minification
CWE: 95, Severity: Low, Tool: Npm Audit

#### Description
Versions of `uglify-js` prior to 2.4.24 are affected by a vulnerability which may cause crafted JavaScript to have altered functionality after minification.


#### Remediation
Upgrade UglifyJS to version >= 2.4.24.
### Evidences

### Application Error Disclosure
CWE: 200, Severity: Medium, Tool: zap

#### Description
This page contains an error/warning message that may disclose sensitive information like the location of the file that produced the unhandled exception. This information can be used to launch further attacks against the web application. The alert could be a false positive if the error message is found inside a documentation page.
#### Remediation
Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user.
### Evidences

#### URL/File/Ref: POST : http://localhost:3000/projects/search_expense_db
### HTTP Only Site
CWE: 311, Severity: Medium, Tool: zap

### Linked Threat Models
* Attacker attempts to compromise auth token by gaining access to the end user's auth token by performing Man in the Middle Attacks

#### Description
The site is only served under HTTP and not HTTPS.
#### Remediation
Configure your web or application server to use SSL (https).
### Evidences

#### URL/File/Ref: GET : http://localhost:3000/
#### Other Info: Failed to connect.
ZAP attempted to connect via: https://localhost:443/
### Insecure Direct Object Reference - Mass Assignment
CWE: 285, Severity: High, Tool: Custom Exploit Script

#### Description
The update expense function is vulnerable to a Mass-Assignment style Insecure Direct Object Reference, where the attacker can guess the name of the named parameters and bypass authorization"
### Evidences

## Reconnaissance

### Reconnaissance Tool: sslyze
#### Target: Cut the Funds Expenser Application

```

{
    "Expect-CT": {
        "CWE": 16, 
        "Description": "The Expect-CT header allows sites to opt in to reporting and/or enforcement of Certificate Transparency requirements, which prevents the use of misissued certificates for that site from going unnoticed."
    }, 
    "TLSv1": {
        "CWE": 326, 
        "suites": [
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        ]
    }, 
    "TLSv1.1": {
        "suites": [
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        ]
    }, 
    "TLSv1.2": {
        "suites": [
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        ]
    }
}
```
