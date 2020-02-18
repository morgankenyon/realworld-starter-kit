open System
open System.IO
open System.Security.Claims
open Microsoft.AspNetCore.Authentication
open Microsoft.AspNetCore.Authentication.JwtBearer
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Logging
open Microsoft.Extensions.DependencyInjection
open Microsoft.IdentityModel.Tokens
open Giraffe
open FSharp.Control.Tasks.V2.ContextInsensitive
open System.Text
open System.Collections.Generic
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Logging

// ---------------------------------
// Web app
// ---------------------------------

[<CLIMutable>]
type User =
    {
        Username : string
        Password : string
        Token : string
    }

[<CLIMutable>]
type LoginAttempt =
    {
        Username : string
        Password : string
    }

type SimpleClaim = { Type: string; Value: string }

let mutable users = List.empty<User>

let secret = "testkey_this_needs_to_be_big_or_else_an_error_occurs"

let authorize =
    requiresAuthentication (challenge JwtBearerDefaults.AuthenticationScheme)

let greet =
    fun (next : HttpFunc) (ctx : HttpContext) ->
        let claim = ctx.User.FindFirst "name"
        let name = claim.Value
        text ("Hello " + name) next ctx

let showClaims =
    fun (next : HttpFunc) (ctx : HttpContext) ->
        let claims = ctx.User.Claims
        let simpleClaims = Seq.map (fun (i : Claim) -> {Type = i.Type; Value = i.Value}) claims
        json simpleClaims next ctx

let compareUsername (user : User ) (username : string) = user.Username = username

let generateToken username =
    let tokenHandler = new JwtSecurityTokenHandler()
    let key = Encoding.ASCII.GetBytes(secret)
    let mutable tokenDescriptor = new SecurityTokenDescriptor()
    let claim = new Claim(ClaimTypes.Name, username)
    let claims = [| claim |]
    tokenDescriptor.Subject <- new ClaimsIdentity(claims)
    tokenDescriptor.Expires <- System.Nullable(DateTime.UtcNow.AddSeconds(30.0))
    tokenDescriptor.SigningCredentials <- new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    let token = tokenHandler.CreateToken(tokenDescriptor)
    tokenHandler.WriteToken(token)

let addUser =
    fun (next : HttpFunc) (ctx : HttpContext) ->
        task {
            let! user = ctx.BindJsonAsync<User>();

            let newUsers = (user :: users)
            users <- newUsers
            let token = generateToken user.Username
            return! Successful.OK token next ctx
        }


let authenticateUser =
    fun (next : HttpFunc) (ctx : HttpContext) ->
        task {
            let! loginAttempt = ctx.BindJsonAsync<LoginAttempt>();

            let usernameAndPasswordMatch loginAttempt (user : User) =
                loginAttempt.Username = user.Username && loginAttempt.Password = user.Password
            
            let matchingUser = 
                users
                |> List.tryFind (fun x -> usernameAndPasswordMatch loginAttempt x)

            match matchingUser with 
            | Some x -> 
                let token = generateToken x.Username
                return! Successful.OK token next ctx
            | None -> return! RequestErrors.UNAUTHORIZED "Basic" "Some Realm" "Unauthorized" next ctx
        }

let getUsers () : HttpHandler =
    fun (next : HttpFunc) (ctx : HttpContext) ->
         Successful.OK users next ctx

//let getUsers () : HttpHandler =
//    json users
//let getUsers = Successful.OK users

let webApp =
    choose [
        GET >=>
            choose [
                route "/" >=> text "Public endpoint."
                route "/greet" >=> authorize >=> greet
                route "/claims" >=> authorize >=> showClaims
                route "/users" >=> authorize >=> getUsers()
            ]
        POST >=>
            choose [
                route "/users/add" >=> addUser
                route "/users/authenticate" >=> authenticateUser
            ]
        setStatusCode 404 >=> text "Not Found" ]

// ---------------------------------
// Error handler
// ---------------------------------

let errorHandler (ex : Exception) (logger : ILogger) =
    logger.LogError(EventId(), ex, "An unhandled exception has occurred while executing the request.")
    clearResponse >=> setStatusCode 500 >=> text ex.Message

// ---------------------------------
// Config and Main
// ---------------------------------

let configureApp (app : IApplicationBuilder) =
    app.UseAuthentication()
       .UseGiraffeErrorHandler(errorHandler)
       .UseStaticFiles()
       .UseGiraffe webApp

let authenticationOptions (o : AuthenticationOptions) =
    o.DefaultAuthenticateScheme <- JwtBearerDefaults.AuthenticationScheme
    o.DefaultChallengeScheme <- JwtBearerDefaults.AuthenticationScheme

let jwtBearerOptions (cfg : JwtBearerOptions) =
    let key = Encoding.ASCII.GetBytes(secret);
    cfg.SaveToken <- true
    cfg.RequireHttpsMetadata <- false
    cfg.TokenValidationParameters <- TokenValidationParameters (
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false,
        ClockSkew = TimeSpan.Zero
    )

let configureServices (services : IServiceCollection) =
    services
        .AddGiraffe()
        .AddAuthentication(authenticationOptions)
        .AddJwtBearer(Action<JwtBearerOptions> jwtBearerOptions) |> ignore

let configureLogging (builder : ILoggingBuilder) =
    let filter (l : LogLevel) = l.Equals LogLevel.Error
    builder.AddFilter(filter).AddConsole().AddDebug() |> ignore

[<EntryPoint>]
let main _ =
    let contentRoot = Directory.GetCurrentDirectory()
    let webRoot     = Path.Combine(contentRoot, "WebRoot")
    WebHostBuilder()
        .UseKestrel()
        .UseContentRoot(contentRoot)
        .UseIISIntegration()
        .UseWebRoot(webRoot)
        .Configure(Action<IApplicationBuilder> configureApp)
        .ConfigureServices(configureServices)
        .ConfigureLogging(configureLogging)
        .Build()
        .Run()
    0