module Db

open System.Data
open Microsoft.Data.SqlClient
open Dapper.FSharp
open Dapper.FSharp.MSSQL
open Models
open System
open FSharp.Control.Tasks.V2
open System.Linq

let connStr = "Data Source=LAPTOP-M5JK4R1J;Initial Catalog=RealWorld;Integrated Security=True"


[<CLIMutable>]
type User = 
    {
        Id : int
        Email : string
        Username : string
        Password : string //needs to be hashed
        Bio : string
        Image : string
        Created : DateTime
        Updated : DateTime
    }

let insertUser (user : UnregisteredUser) =
    task {
        use conn : IDbConnection = new SqlConnection(connStr) :> IDbConnection
        conn.Open()

        let insertStmt = insert {
            table "Users"
            value {| Email = user.Email; Username = user.Email; Password = user.Password; Bio = ""; Image = ""; Created = DateTime.UtcNow; Updated = DateTime.UtcNow |}
        } 

        let! insertedCount = insertStmt |> conn.InsertAsync
        return insertedCount
    }

let selectUser (email : string) (password : string) =
    task {
        use conn : IDbConnection = new SqlConnection(connStr) :> IDbConnection
        conn.Open()

        let selectStmt = select {
            table "Users"
            where (eq "Email" email + eq "Password" password)
        }

        let! dbUsers = selectStmt |> conn.SelectAsync<User>

        
        //let firstUser = dbUsers.First()

        //return { Email = firstUser.Email; Username = firstUser.Username; Bio = firstUser.Bio; Image = firstUser.Image }

        
        return dbUsers.First() //do some mapping
    }
    