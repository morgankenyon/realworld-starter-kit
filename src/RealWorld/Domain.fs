module Domain

open FSharp.Control.Tasks.V2
open System.Threading.Tasks
open Models

let RegisterUser (user : UnregisteredUser) (generateToken : string -> string) (userInsert : Task<int> )=  
    task {

        let! _ = userInsert
        let token = generateToken user.Email

        return { Email = user.Email; Username = user.Username; Bio = ""; Image = ""; Token = token }
    }

let AuthenticateUser (generateToken : string -> string) (userSelect : Task<Db.User>) =
    task {
            
        let! dbUser = userSelect

        let token = generateToken dbUser.Email

        return { Email = dbUser.Email; Username = dbUser.Username; Bio = dbUser.Bio; Image = dbUser.Image; Token = token }
    }

let GetLoggedInUser (userSelect : Task<Db.User>)=
    task {

        let! dbUser = userSelect
            
        return { Email = dbUser.Email; Username = dbUser.Username; Bio = dbUser.Bio; Image = dbUser.Image; Token = "" }
        
    }