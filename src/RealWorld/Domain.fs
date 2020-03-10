module Domain

open Models

let RegisterUser (generateToken : string -> string) (user : UnregisteredUser) : AuthorizedUser =  
    let token = generateToken user.Email
    { Email = user.Email; Username = user.Username; Bio = ""; Image = ""; Token = token }

let AuthenticateUser (generateToken : string -> string) (user : Db.User) : AuthorizedUser =
    let token = generateToken user.Email
    { Email = user.Email; Username = user.Username; Bio = user.Bio; Image = user.Image; Token = token }

let MapDbUser (user : Db.User) : AuthorizedUser =            
    { Email = user.Email; Username = user.Username; Bio = user.Bio; Image = user.Image; Token = "" }