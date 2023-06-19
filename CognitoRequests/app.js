const AWS = require('aws-sdk');
const https = require('https');
const url = require('url');

const COGNITO_CLIENT = new AWS.CognitoIdentityServiceProvider({
  apiVersion: "2016-04-19",
  region: process.env.REGION
});

let list = [];

/**
 *
 * Cognito Request Handler.
 * 
 */
exports.lambdaHandler = async (event, context) => {

  console.info(JSON.stringify(event));

  let path = event.path;
  let redirectUri = getRedirectUri(event);
  const allowedGroup = process.env.GROUP;

  function adminAction(func, obj) {
    let groups;
    let isAdmin;
    if (event.requestContext.authorizer && event.requestContext.authorizer.claims['cognito:groups']) {
      groups = event.requestContext.authorizer.claims['cognito:groups'];
      isAdmin = groups.indexOf(allowedGroup);
    }
    if (isAdmin > -1) {
      return func(obj);
    } else {
      return response(201, { message: "User does not have permissions to perform administrative tasks" });
    }
  }

  if (path != null && event.body != null) {

    var body = event.body;
    if (event.isBase64Encoded) {
      let buff = Buffer.from(body, 'base64');
      body = buff.toString('utf-8');
    }

    let obj = JSON.parse(body);

    if (path == "/register") {
      return handleRegister(obj);
    } else if (path == "/login") {
      return login(obj, redirectUri);
    } else if (path == "/changePassword") {
      return changepassword(obj);
    } else if (path == "/forgotPassword") {
      return forgotPassword(obj);
    } else if (path == "/resetPassword") {
      return resetPassword(obj);
    } else if (path == "/refreshToken") {
      return refreshToken(obj);
    } else if (path == "/respondToAuthChallenge") {
      return respondToAuthChallenge(obj);
    } else if (path == "/createUser") {
      return adminAction(createUser, obj);
    } else if (path == "/addUserToGroup") {
      return adminAction(addUsersToGroup, obj);
    } else if (path == "/updateUserAttributes") {
      return adminAction(updateUserAttributes, obj);
    } else if (path == "/createGroup") {
      return adminAction(createGroup, obj);
    } else if (path == "/listGroupsForUser") {
      return adminAction(listGroupsForUser, obj);
    } else if (path == "/listUsersInGroup") {
      return adminAction(listUsersInGroup, obj);
    } else if (path == "/listGroups") {
      return adminAction(listGroups, obj);
    } else if (path == "/listUsers") {
      return adminAction(listUsers, obj);
    } else if (path == "/removeUserFromGroup") {
      return adminAction(removeUsersFromGroup, obj);
    } else {
      return response(400, { message: "invalid request" });
    }
  } else if (path != null && path == "/confirmSignUp") {
    return confirmSignUp(event, redirectUri);
  } else if (path != null && path == "/confirmRegistration") {
    return confirmRegistration(event, redirectUri);
  } else if (path != null && path == "/listGroups") {
    return adminAction(listGroups);
  } else if (path != null && path == "/listUsers") {
    return adminAction(listUsers);
  } else if (path != null && event.pathParameters != null) {

    var obj = event.pathParameters;
    if (event.isBase64Encoded) {
      let buff = Buffer.from(obj, 'base64');
      obj = buff.toString('utf-8');
    }

    if (path.split("/")[1] == "deleteGroup") {
      return adminAction(deleteGroup, obj);
    } else if (path.split("/")[1] == "getUser") {
      return adminAction(getUserData, obj);
    } else if (path.split("/")[1] == "deleteUser") {
      return adminAction(deleteUser, obj);
    } else {
      return response(400, { message: "invalid request" });
    }
  } else if (event.httpMethod == "OPTIONS") {
    return response(200, { message: "it's all good" });
  } else {
    return response(400, { message: "invalid body" });
  }
};

function confirmRegistration(event, redirectUri) {

  let code = event.queryStringParameters.code;
  let username = event.queryStringParameters.username;
  let userStatus = event.queryStringParameters.userStatus;
  var session = "";

  return login({ username: username, password: code }, redirectUri).then((data) => {
    var body = JSON.parse(data.body);
    if (body.ChallengeName == "NEW_PASSWORD_REQUIRED") {
      userStatus = "NEW_PASSWORD_REQUIRED";
      session = body.Session;
    }

    return response(301, redirectUri + "?success=true&username=" + username + "&userStatus=" + userStatus + "&code=" + encodeURIComponent(code) + "&session=" + encodeURIComponent(session));
  }).catch((error) => {
    console.log("ERROR: " + JSON.stringify(error));
    return response(301, redirectUri + "?success=false&username=" + username + "&userStatus=" + userStatus + "&code=" + encodeURIComponent(code) + "&session=" + encodeURIComponent(session));
  });
}

function confirmSignUp(event, redirectUri) {

  let code = event.queryStringParameters.code;
  let username = event.queryStringParameters.username;
  let userStatus = event.queryStringParameters.userStatus;

  let params = {
    ClientId: process.env.POOL_CLIENT_ID,
    ConfirmationCode: code,
    Username: username
  };

  return COGNITO_CLIENT.confirmSignUp(params).promise().then((data) => {
    return response(301, redirectUri + "?success=true&username=" + username + "&userStatus=" + userStatus);
  }).catch((error) => {
    console.log("ERROR: " + error);
    return response(301, redirectUri + "?success=false&username=" + username + "&userStatus=" + userStatus);
  });
}

function resetPassword(obj) {

  let params = {
    ClientId: process.env.POOL_CLIENT_ID,
    ConfirmationCode: obj.code,
    Username: obj.username,
    Password: obj.password
  };

  return COGNITO_CLIENT.confirmForgotPassword(params).promise().then((data) => {
    return response(200, { message: "Password Updated" });
  }).catch((error) => {
    console.log("ERROR: " + error);
    return response(400, error);
  });
}

function handleRegister(obj) {
  let requiredFields = ["username", "password"];

  if (isValidFields(obj, requiredFields)) {

    let createGroup = obj.createNewGroup != null;
    let confirmSignUp = obj.confirmSignUp != null;

    var params = {
      ClientId: process.env.POOL_CLIENT_ID,
      Password: obj.password,
      Username: obj.username
    };

    return COGNITO_CLIENT.signUp(params).promise().then((data) => {

      var groupName = randomString(10, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
      var params = {
        GroupName: groupName,
        UserPoolId: process.env.USER_POOL_ID
      };

      return (createGroup ? COGNITO_CLIENT.createGroup(params).promise().then((data) => {

        var params = {
          GroupName: groupName,
          UserPoolId: process.env.USER_POOL_ID,
          Username: obj.username
        };

        return COGNITO_CLIENT.adminAddUserToGroup(params).promise();

      }) : Promise.resolve("")).then(() => {

        var params = {
          UserPoolId: process.env.USER_POOL_ID,
          Username: obj.username
        };

        return confirmSignUp ? COGNITO_CLIENT.adminConfirmSignUp(params).promise() : Promise.resolve("no confirmSignUp");

      }).then(() => {

        var params = {
          UserAttributes: [
            {
              Name: 'email_verified',
              Value: 'true'
            }
          ],
          UserPoolId: process.env.USER_POOL_ID,
          Username: obj.username
        };

        return confirmSignUp ? COGNITO_CLIENT.adminUpdateUserAttributes(params).promise() : Promise.resolve("no confirmSignUp");

      }).then((data) => {
        return response(200, { message: "User registered" });
      });

    }).catch((error) => {
      console.log("ERROR: " + error);
      return response(400, error);
    });

  } else {
    return response(400, { message: "missing fields 'username', 'password'" });
  }
}

function respondToAuthChallenge(obj) {
  let requiredFields = ["session", "password", "username", "userStatus"];

  if (isValidFields(obj, requiredFields)) {

    var params = {
      ClientId: process.env.POOL_CLIENT_ID,
      ChallengeName: obj.userStatus,
      Session: decodeURIComponent(obj.session),
      ChallengeResponses: {
        NEW_PASSWORD: obj.password,
        USERNAME: obj.username
      }
    };

    return COGNITO_CLIENT.respondToAuthChallenge(params).promise().then((data) => {
      return response(200, { message: "Change Password" });
    }).catch((error) => {
      return response(400, error);
    });

  } else {
    return response(400, { message: "missing fields 'userStatus','session','password','username'" });
  }
}

function changepassword(obj) {
  let requiredFields = ["accessToken", "password", "previousPassword"];

  if (isValidFields(obj, requiredFields)) {

    var params = {
      PreviousPassword: obj.previousPassword,
      ProposedPassword: obj.password,
      AccessToken: obj.accessToken
    };

    return COGNITO_CLIENT.changePassword(params).promise().then((data) => {
      return response(200, { message: "Change Password" });
    }).catch((error) => {
      return response(400, error);
    });

  } else {
    return response(400, { message: "missing fields 'accessToken','password','previousPassword'" });
  }
}

function getUser(username) {
  var params = {
    UserPoolId: process.env.USER_POOL_ID,
    Username: username
  };
  return COGNITO_CLIENT.adminGetUser(params).promise();
}

function fixForcePasswordChange(username) {
  return getUser(username).then((user) => {
    if ("FORCE_CHANGE_PASSWORD" === user.UserStatus) {
      var password = randomString(16, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
      var params = {
        Password: password,
        UserPoolId: process.env.USER_POOL_ID,
        Username: username,
        Permanent: true
      };
      return COGNITO_CLIENT.adminSetUserPassword(params).promise();
    } else {
      return Promise.resolve("");
    }
  });
}

function forgotPassword(obj) {
  let requiredFields = ["username"];

  if (isValidFields(obj, requiredFields)) {

    return fixForcePasswordChange(obj.username).then(() => {

      var params = {
        ClientId: process.env.POOL_CLIENT_ID,
        Username: obj.username
      };

      return COGNITO_CLIENT.forgotPassword(params).promise().then((data) => {
        return response(200, { message: "Password reset sent" });
      }).catch((error) => {
        return response(400, error);
      });

    }).catch((error) => {
      if (error.code === "UserNotFoundException") {
        return response(201, { message: "This email is not registered" });
      } else {
        return response(400, error);
      }
    });

  } else {
    return response(400, { message: "missing fields 'username'" });
  }
}

function loginOAuth2(code, redirectUri) {

  let u = url.parse(process.env.COGNITO_DOMAIN);
  let path = "/oauth2/token?grant_type=authorization_code&client_id=" + process.env.POOL_CLIENT_ID
    + "&code=" + code + "&redirect_uri=" + redirectUri;

  var opts = {
    host: u.hostname,
    path: path,
    method: 'POST',
    body: '',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  };

  return new Promise((resolve, reject) => {
    send(opts, resolve, reject);
  }).then((data) => {

    let obj = JSON.parse(data);
    let o = {
      AuthenticationResult: {
        AccessToken: obj['access_token'],
        IdToken: obj['id_token'],
        RefreshToken: obj['refresh_token'],
        ExpiresIn: obj['expires_in']
      }
    };

    var opts2 = {
      host: u.hostname,
      path: '/oauth2/userInfo',
      method: 'GET',
      body: '',
      headers: {
        'Authorization': 'Bearer ' + obj['access_token']
      }
    };

    return new Promise((resolve, reject) => {
      send(opts2, resolve, reject);
    }).then((data) => {
      let user = JSON.parse(data);
      o.AuthenticationResult.username = user.username;
      o.AuthenticationResult.email = user.email;
      return response(200, o);
    });

  }).catch(() => {
    return response(301, redirectUri + "?success=false");
  });
}

function send(opts, resolve, reject) {
  const req = https.request(opts, res => {
    console.log("statusCode: " + res.statusCode);

    var body = '';

    res.on('data', chunk => {
      body += chunk;
    });

    res.on('end', () => {
      console.log("BODY: " + body);

      if (res.statusCode == 200 || res.statusCode == 201) {
        resolve(body);
      } else {
        reject({ statusCode: res.statusCode, body: body });
      }
    });
  });

  req.on('error', error => {
    reject(error);
  });

  req.write(opts.body);
  req.end();
}

function login(obj, redirectUri) {

  let requiredFields = ["username", "password"];
  if (isValidFields(obj, requiredFields)) {

    var params = {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: process.env.POOL_CLIENT_ID,
      AuthParameters: {
        'USERNAME': obj.username,
        'PASSWORD': obj.password
      }
    };

    return COGNITO_CLIENT.initiateAuth(params).promise().then((data) => {
      return response(200, data);
    }).catch((error) => {
      return response(400, error);
    });

  } else if (obj.code) {
    return loginOAuth2(obj.code, redirectUri);
  } else {
    return response(400, { message: "missing fields 'username'" });
  }
}

function refreshToken(obj) {
  let requiredFields = ["refreshToken"];

  if (isValidFields(obj, requiredFields)) {

    var params = {
      AuthFlow: "REFRESH_TOKEN_AUTH",
      ClientId: process.env.POOL_CLIENT_ID,
      AuthParameters: {
        'REFRESH_TOKEN': obj.refreshToken
      }
    };

    return COGNITO_CLIENT.initiateAuth(params).promise().then((data) => {
      return response(200, data);
    }).catch((error) => {
      return response(400, error);
    });

  } else {
    return response(400, { message: "missing fields 'username'" });
  }
}

function response(statusCode, message) {

  var resp = {};
  if (statusCode == 301) {
    resp = {
      'statusCode': statusCode,
      headers: {
        Location: message,
      }
    };
  } else {
    resp = {
      'statusCode': statusCode,
      'body': JSON.stringify(message)
    };
  }

  console.log(JSON.stringify(resp));
  return resp;
}

function isValidFields(obj, requiredFields) {

  var valid = true;

  requiredFields.forEach(element => {
    if (obj[element] === undefined) {
      valid = false;
    }
  });

  return valid;
}

function randomString(length, chars) {
  var result = '';
  for (var i = length; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
  return result;
}

function getRedirectUri(event) {

  var validHosts = process.env.REDIRECT_URI.split(",");
  var uri = validHosts[0];

  if (event.queryStringParameters != null && event.queryStringParameters["redirect_uri"] != null) {
    let newRedirect = decodeURIComponent(event.queryStringParameters["redirect_uri"]);

    const found = validHosts.find(element => newRedirect.startsWith(element));
    if (found) {
      uri = newRedirect;
    }
  }

  return uri;
}

function createUser(obj) {
  let requiredFields = ["username", "name"];
  if (isValidFields(obj, requiredFields)) {
    var params = {
      UserPoolId: process.env.USER_POOL_ID,
      Username: obj.username,
      UserAttributes: [
        {
          Name: 'email',
          Value: obj.username
        },
        {
          Name: 'email_verified',
          Value: 'true'
        },
        {
          Name: 'name',
          Value: obj.name
        }
      ]
    };

    return COGNITO_CLIENT.adminCreateUser(params).promise().then((data) => {
      var params = {
        GroupName: "default_read",
        UserPoolId: process.env.USER_POOL_ID,
        Username: obj.username
      };

      return COGNITO_CLIENT.adminAddUserToGroup(params).promise().then((dataGroup) => {
        return response(200, { message: "user created and added to default (read access) group", data: data });
      }).catch((error) => {
        return response(400, error);
      });
    }).catch((error) => {
      return response(400, error);
    });
  } else {
    return response(400, { message: "missing fields 'username', 'name" });
  }
}

function deleteUser(obj) {
  let requiredFields = ["username"];
  if (isValidFields(obj, requiredFields)) {
    var params = {
      UserPoolId: process.env.USER_POOL_ID,
      Username: obj.username
    };

    return COGNITO_CLIENT.adminDeleteUser(params).promise().then((data) => {
      return response(200, { message: "user deleted", data: data });
    }).catch((error) => {
      return response(400, error);
    });
  } else {
    return response(400, { message: "missing fields 'username'" });
  }
}

function addUserToGroup(obj) {
  let groupName;
  let groupList = [];
  let reverseGroup;
  let requiredFields = ["username", "groupname"];
  if (isValidFields(obj, requiredFields)) {
    groupName = obj.groupname;
    reverseGroup = `${obj.groupname}_read`;
    if (obj.readOnly && obj.readOnly == 1) {
      groupName = `${obj.groupname}_read`;
      reverseGroup = obj.groupname;
    }
    var params = {
      GroupName: groupName,
      UserPoolId: process.env.USER_POOL_ID,
      Username: obj.username
    };

    return COGNITO_CLIENT.adminAddUserToGroup(params).promise().then((data) => {
      var paramsUser = {
        UserPoolId: process.env.USER_POOL_ID,
        Username: obj.username
      };

      return COGNITO_CLIENT.adminListGroupsForUser(paramsUser).promise().then((data) => {
        for (let i = 0; i < data.Groups.length; i++) {
          groupList.push(data.Groups[i].GroupName);
        }
        if (groupList.indexOf(reverseGroup) > -1) {
          var params = {
            GroupName: reverseGroup,
            UserPoolId: process.env.USER_POOL_ID,
            Username: obj.username
          };

          return COGNITO_CLIENT.adminRemoveUserFromGroup(params).promise().then((data) => {
            return { statusCode : 200 , message : data}
          }).catch((error) => {
            return { statusCode : 400 , message : error }
          });
        }
        return { statusCode : 200 , message : data }
      }).catch((error) => {
        return { statusCode : 400 , message : error }
      });
    }).catch((error) => {
      return { statusCode : 400 , message : error }
    });
  } else {
    return { statusCode : 400, message : "missing fields 'username', 'groupname'" }
  }
}

async function addUsersToGroup(obj) {
  let users = obj.users;
  for (let i = 0; i < users.length; i++) {
    users[i]["groupname"] = obj.groupname;
    let add = await addUserToGroup(users[i])
    if(add.statusCode == 400){
      return response(400, { message : add.message })
    }
  }
  return response(200, { message: "users added to group" })
}

function removeUserFromGroup(obj) {
  let groupList = [];
  let requiredFields = ["username", "groupname"];
  if (isValidFields(obj, requiredFields)) {
    var paramsUser = {
      UserPoolId: process.env.USER_POOL_ID,
      Username: obj.username
    };

    return COGNITO_CLIENT.adminListGroupsForUser(paramsUser).promise().then((data) => {
      for (let i = 0; i < data.Groups.length; i++) {
        groupList.push(data.Groups[i].GroupName);
      }
      if (groupList.indexOf(obj.groupname) > -1) {
        var params = {
          GroupName: obj.groupname,
          UserPoolId: process.env.USER_POOL_ID,
          Username: obj.username
        };
        return COGNITO_CLIENT.adminRemoveUserFromGroup(params).promise().then((data) => {
          return { statusCode : 200 , message : data };
        }).catch((error) => {
          return { statusCode : 400 , message : error };
        });
      } else if (groupList.indexOf(`${obj.groupname}_read`) > -1) {
        var params = {
          GroupName: `${obj.groupname}_read`,
          UserPoolId: process.env.USER_POOL_ID,
          Username: obj.username
        };
        return COGNITO_CLIENT.adminRemoveUserFromGroup(params).promise().then((data) => {
          return { statusCode : 200 , message : data };
        }).catch((error) => {
          return { statusCode : 400 , message : error };
        });
      } else {
        return { statusCode : 201, message : "user is not in group" };
      }
    }).catch((error) => {
      return { statusCode : 400 , message : error }
    });
  } else {
    return { statusCode : 400 , message : "missing fields 'username', 'groupname'" };
  }
}

async function removeUsersFromGroup(obj) {
  let users = obj.users;
  for (let i = 0; i < users.length; i++) {
    users[i]["groupname"] = obj.groupname;
    let remove = await removeUserFromGroup(users[i]);
    if(remove.statusCode == 400){
      return response(400, { message : remove.message })
    }else if (remove.statusCode == 201){
      return response(201, { message : remove.message})
    }
  }
  return response(200, { message: "users removed from group" })
}

function listGroups(obj) {
  let nextToken;
  let limit;
  if (obj && obj.nextToken) {
    nextToken = obj.nextToken;
  }
  if (obj && obj.limit) {
    limit = obj.limit;
  }
  var params = {
    UserPoolId: process.env.USER_POOL_ID,
    Limit: limit,
    NextToken: nextToken
  };

  return COGNITO_CLIENT.listGroups(params).promise().then((data) => {
    for (var i = 0; i < data.Groups.length; i++) {
      if (data.Groups[i].GroupName.includes("_read")) {
        data.Groups.splice(i, 1);
      } else if (data.Groups[i].GroupName === "Admins") {
        data.Groups.splice(i, 1);
      }
    }
    list = list.concat(data.Groups);
    if (data.NextToken && !limit) {
      obj["nextToken"] = data.NextToken;
      return listGroups(obj);
    } else {
      data.Groups = list;
      list = [];
      return response(200, { message: "list group", data: data });
    }

  }).catch((error) => {
    return response(400, error);
  });
}

function listUsers(obj) {
  let paginationToken;
  let limit;
  if (obj && obj.paginationToken) {
    paginationToken = obj.paginationToken;
  }
  if (obj && obj.limit) {
    limit = obj.limit;
  }
  var params = {
    UserPoolId: process.env.USER_POOL_ID,
    Limit: limit,
    PaginationToken: paginationToken
  };
  return COGNITO_CLIENT.listUsers(params).promise().then((data) => {
    list = list.concat(data.Users);
    if (data.PaginationToken && !limit) {
      obj["paginationToken"] = data.PaginationToken;
      return listUsers(obj);
    } else {
      data.Users = list;
      list = [];
      return response(200, { message: "list users", data: data });
    }
  }).catch((error) => {
    return response(400, error);
  });
}

function listUsersInGroup(obj) {
  let requiredFields = ["groupname"];
  let nextToken;
  let limit;
  let groupName;
  if (isValidFields(obj, requiredFields)) {
    groupName = obj.groupname;
    if (obj && obj.nextToken) {
      nextToken = obj.nextToken;
    }
    if (obj && obj.limit) {
      limit = obj.limit;
    }
    if (obj && obj.readOnly == 1) {
      groupName = `${obj.groupname}_read`;
    }
    var params = {
      UserPoolId: process.env.USER_POOL_ID,
      GroupName: groupName,
      Limit: limit,
      NextToken: nextToken
    };

    return COGNITO_CLIENT.listUsersInGroup(params).promise().then((data) => {
      list = list.concat(data.Users);
      if (data.NextToken && !limit) {
        obj["nextToken"] = data.NextToken;
        return listUsersInGroup(obj);
      } else {
        data.Users = list;
        list = [];
        return response(200, { message: "list users", data: data });
      }
    }).catch((error) => {
      return response(400, error);
    });
  } else {
    return response(400, { message: "missing fields 'groupname'" });
  }
}

function listGroupsForUser(obj) {
  let requiredFields = ["username"];
  let nextToken;
  let limit;
  if (isValidFields(obj, requiredFields)) {
    if (obj && obj.nextToken) {
      nextToken = obj.nextToken;
    }
    if (obj && obj.limit) {
      limit = obj.limit;
    }
    var params = {
      UserPoolId: process.env.USER_POOL_ID,
      Username: obj.username,
      Limit: limit,
      NextToken: nextToken
    };

    return COGNITO_CLIENT.adminListGroupsForUser(params).promise().then((data) => {
      list = list.concat(data.Groups);
      if (data.NextToken && !limit) {
        obj["nextToken"] = data.NextToken;
        return listGroupsForUser(obj);
      } else {
        data.Groups = list;
        list = [];
        return response(200, { message: "list of groups for user", data: data });
      }
    }).catch((error) => {
      return response(400, error);
    });
  } else {
    return response(400, { message: "missing fields 'username'" });
  }
}

function updateUserAttributes(obj) {
  let requiredFields = ["username", "name"];
  if (isValidFields(obj, requiredFields)) {
    var params = {
      UserPoolId: process.env.USER_POOL_ID,
      Username: obj.username,
      UserAttributes: [
        {
          Name: 'name',
          Value: obj.name
        }
      ]
    };

    return COGNITO_CLIENT.adminUpdateUserAttributes(params).promise().then((data) => {
      return response(200, { message: "updated user attributes", data: data });
    }).catch((error) => {
      return response(400, error);
    });
  } else {
    return response(400, { message: "missing required fields" });
  }
}

function getUserData(obj) {
  let requiredFields = ["username"];
  if (isValidFields(obj, requiredFields)) {
    var params = {
      UserPoolId: process.env.USER_POOL_ID,
      Username: obj.username,
    };

    return COGNITO_CLIENT.adminGetUser(params).promise().then((data) => {
      var paramsGroup = {
        UserPoolId: process.env.USER_POOL_ID,
        Username: obj.username
      };

      return COGNITO_CLIENT.adminListGroupsForUser(paramsGroup).promise().then((dataGroup) => {
        data["UserGroups"] = dataGroup.Groups;
        return response(200, { message: "user data", data: data });
      }).catch((error) => {
        return response(400, error);
      });
    }).catch((error) => {
      return response(400, error);
    });
  } else {
    return response(400, { message: "missing required fields" });
  }
}

function createGroup(obj) {
  let requiredFields = ["groupname"];
  if (isValidFields(obj, requiredFields)) {
    var paramsRead = {
      UserPoolId: process.env.USER_POOL_ID,
      GroupName: `${obj.groupname}_read`,
      Description: `read only access to ${obj.groupname}`
    };

    return COGNITO_CLIENT.createGroup(paramsRead).promise().then((data) => {
      var params = {
        UserPoolId: process.env.USER_POOL_ID,
        GroupName: obj.groupname,
        Description: obj.description
      };
      
      return COGNITO_CLIENT.createGroup(params).promise().then((data) => {
        return response(200, { message: "group created", data: data });
      }).catch((error) => {
        return response(400, error);
      });
    }).catch((error) => {
      return response(400, error);
    });
  } else {
    return response(400, { message: "missing required fields" });
  }
}

function deleteGroup(obj) {
  let requiredFields = ["groupname"];
  if (isValidFields(obj, requiredFields)) {
    var paramsRead = {
      UserPoolId: process.env.USER_POOL_ID,
      GroupName: `${obj.groupname}_read`
    };

    return COGNITO_CLIENT.deleteGroup(paramsRead).promise().then((data) => {
      var params = {
        UserPoolId: process.env.USER_POOL_ID,
        GroupName: obj.groupname
      };

      return COGNITO_CLIENT.deleteGroup(params).promise().then((data) => {
        return response(200, { message: "group deleted" });
      }).catch((error) => {
        return response(400, error);
      });
    }).catch((error) => {
      return response(400, error);
    });
  } else {
    return response(400, { message: "missing required fields" });
  }
}