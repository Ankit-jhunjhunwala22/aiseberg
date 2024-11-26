Authentication system:
1) auth.py routes are managed by auth_service defined in auth_service.py
2) google_auth.py routes manage google openid connect 



File upload system
1) file.py routes are managed by  file_service defined in file_service.py



Role based access and permission based access
1) We have Two roles by Default - Admin and User
2) We have Three permission by default - View_all, View_own and upload
3) we have user_roles table to add many to many relationship to effectively manage role based and permission based access
4) defined two decorator permission_required and role_required to add on routes where we need relavent role and permission based checks, database models are defined in models.py



Authentication System:


    Email/Password Authentication password reset flow
        1) password resets
            1.1) First user initiate password reset by hitting
                [POST] /auth/password-reset-request
                {
                    "email": "sample@gmail.com"
                } 
            we will validate that we have a user with the given email and it was not created via google open id connect based in field google_id (should be null)

            1.2) we generate a new jwt token (reset token) in auth_service.request_password_reset method with expiration ttl

        2) A reset link is generated and sent to user email - sample reset link = [GET] http://file_frontend.com/reset-password?token={reset_token}
        3) once the user clicks on reset link, he will be directed to file.com ui asking for new password
        4) user will add new password then ui will hit post call
            [POST] /auth/reset-password
            {
                "token":<reet token>,
                "new_password": <new passowrd>
            }
        5) /auth/reset-password will validate token passed, and if the token is valid, new_password will be set for the user.





    Email/Password Authentication account lock out flow
        1) we have defined two configs MAX_FAILED_ATTEMPTS = 5 (Maximum allowed failed attempts) LOCKOUT_DURATION = 15(Lockout period in minutes)
        2) we have column "last_failed_attempt" in users table, this column tells us when was the last uncessful login attempt, column "failed_attempts" that counts the consecutive failed atempt to login by user and is_locked column which tells whether user account is locked
        3) in auth_Service.login_with_email_password method, we check if the user have >= MAX_FAILED_ATTEMPTS then we lock the user account by setting is_locked to true for LOCKOUT_DURATION
        4) if the account is locked, user has to wait for LOCKOUT_DURATION to retry again
        5) once user sucessfully logins after the LOCKOUT_DURATION, we reset failed_attempts = 0 and is_locked = False






    Google Sign-In Integration: (we will be using openid connect for google)
        1) When user clicks on google sign in option, our file.com ui will call [GET]/google/login
        2) [GET]/google/login will redirect user to google authorization server along with a callback url which is "/google/callback" in our case
        3) User will sign in using their credential on google authorization server
        4) If successful, google authorization server will generate a authorization code and redirect user to our /google/callback along with authorization code
        5) id token, access token are exchanged using authorization code when /google/callback endpoint is hit
        6) we validate id token using public key of google authorization server, if sucessful we find the associated claim - email from id token
        7) we create new user if there no user found based on email found in id token, then we generate JWT ACCESS token and referesh token for further session management





    Session Management:
        we are using JWT token for session management

        1) once the user logsin whether via email/password or via google sign openid connect we generate access token with a validity of ACCESS_TOKEN_TTL (1 hr) and refresh token with a validity of REFRESH_TOKEN_TTL (1 weeek)

        2) every protected route like /auth/assign_role or /files/upload will go through a middleware @jwt_required() which will validate the token and only if the token is valid it will allow the end point to handle the request

        3) once the token is decoded, depending on whether we require role based access or permission based access, we have defined two decorator permission_required or role_required in auth_ervice, it will check if the user is of relevant role or have relevant permission

        4) On the frontend, once the access token exppires, front end calls
            [POST] /auth/refresh endpoint to generate new access token
            4.1) jwt_refresh_token_required helps us to decode and validate refresh token
            4.2) once validated, we generate new access token and also rotate refresh token for better security


    
File Upload and Storage System:

    Design
        1) we are using mysql to store meta data related to files like file name, owner id etc
            1.1) we cho0se relational db since we have structed data and here since it is monolithic system we can enforce refrencuial integrity using user id.
        2) file is stored in s3 object storage whose url is stored in file meta data
            2.1) we choose object storage because we will not update the data, it will be used for deletion and addition so we don't need added indexing capabilities that increases latency in relational or nosql kind of data base
        3) File size check
            3.1) we are reading file data in chuncks of 1mb from the client, once the total data exceed FILE_SIZE_LIMIT (5mb) we raise an error "File exceeds the maximum size of 5 MB"
        4) Protocol : http 1.1 with tls 1.3, assuming client is not uploading multiple files in single requests, using http 1.1 will help us to send file meta data in json which will help in debugging and file data will be send as binary. http1.1 will have persistent connection and since we are suming we are seding one file at a time from client we don't require multiplexing if we would have use http2



    Security:
        1) we are using tls to encrypt data from client to backend and on backend we first generate checksum of file store it in file meta data and store the encrypted file data in s3
        2) while fetching file, we decrypt the file data fetched from s3, again generate the checksum and match it with corresponding checksum in file meta data table, this ensures that we have securely saved the file and interity is assured and we can gurantee that file can not be malicious.
        3) we have defined roles and implemenedted permission based access for each action like uploading, viewing per role. it gives an extra layer of security to make relavant changes. 
            3.1) consider [GET] /files in server/file.py. we have two decorator permission_required and role_required in auth_Service
            3.2) since @jwt_required() is the middle ware, request is checked for valid jwt token
            3.2) /files request is decorated with decorator @auth_service.permission_required(Config.VIEW_ALL_PERMISSION, Config.VIEW_OWN_PERMISSION), i.e this route can be accessed by the user whose role has Config.VIEW_ALL_PERMISSION, Config.VIEW_OWN_PERMISSION permissions.
            3.3) in permission_required, we fetch the user id from jwt access token, and check if the user have any permission mentioned in the decorator
                3.3.1) we want to list all files (this is valid for both Admin role and User role)
                3.3.2) ADMIN HAS Config.VIEW_ALL_PERMISSION, Config.VIEW_OWN_PERMISSION
                3.3.3) user HAS Config.VIEW_OWN_PERMISSION
                3.3.4) this route is allowed for both admin/user
                3.3.5) so if the user only have Config.VIEW_OWN_PERMISSION, we list all the files of that user else we list all the files of all the users
            3.4) since one user can have one or more role and every role can have one or more permission, this is scable approach which helps us to provide both role base access(group wise control access) and permission base access (granualar control access)



    Scalability: 
        1) To upgrade this to highly scable system we have to split our system into 1) authentication service 2) file service
        2) we can have multiple instance of authencation service and file service which can autoscaled based on our monitoring of cpu/memory usage. the goal is to make this services stateless
        3) our auhentication service can be sharded on id (which will be generated from a sequence service and it will be montically increasing), each parion will be also replaicated. if we decide on three main node to host our suthentication service we can have a replication factor of 2
        4) Similary we shard and partion our file meta data on file id, here again id is monontonically increasing id generted from a sequence service
        5) Object storage like s3 can easily scale to million request per second
        6) and sharding and partioning of our authentication and file meta data will helps to scale it to million of requests
        7) user request will come to api gateway which will autheicate the request by validating jwt tokens and route to relavent service load balancer, which will then load balance the request to proper shard.
        8) Replication provides us fault tolerance, so we can multi data center replication done asyncrously to manage back up and diaster recovery
        

            

