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
type UnregisteredUser =
    {
        Email : string
        Password : string
        Username : string
    }

[<CLIMutable>]
type AuthorizedUser =
    {
        Email : string
        Username : string
        Bio : string
        Image : string
        Token : string
    }

[<CLIMutable>]
type UnauthorizedUser =
    {
        Email : string
        Password : string
    }

[<CLIMutable>]
type RegisterRequest =
    {
        User : UnregisteredUser
    }

[<CLIMutable>]
type AuthorizedResponse =
    {
        User : AuthorizedUser
    }

[<CLIMutable>]
type UnauthorizedRequest =
    {
        User : UnauthorizedUser
    }

//[<CLIMutable>]
//type LoginRequest =
//    {
//        User : 
//    }

type SimpleClaim = { Type: string; Value: string }

let mutable users = List.empty<UnregisteredUser>

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

let getLoggedInUserHandle =
    fun (next : HttpFunc) (ctx : HttpContext) ->
        let user = ctx.User
        
        let username = user.Identity.Name
        
        //probably should move this match to email, something more unique than username
        let matchUsername (username : string) (user : UnregisteredUser) =
            username = user.Username
        
        let matchingUser = 
            users
            |> List.find (fun x -> matchUsername username x)
            
        let authorizedUser = { Email = matchingUser.Email; Username = matchingUser.Username; Bio = ""; Image = ""; Token = "" } //how to get current token
        let response : AuthorizedResponse = { User = authorizedUser }
        
        json response next ctx

let compareUsername (user : UnregisteredUser ) (username : string) = user.Username = username

let generateToken username =
    let tokenHandler = new JwtSecurityTokenHandler()
    let key = Encoding.ASCII.GetBytes(secret)
    let mutable tokenDescriptor = new SecurityTokenDescriptor()
    let claim = new Claim(ClaimTypes.Name, username)
    let claims = [| claim |]
    tokenDescriptor.Subject <- new ClaimsIdentity(claims)
    tokenDescriptor.Expires <- System.Nullable(DateTime.UtcNow.AddMinutes(2.0))
    tokenDescriptor.SigningCredentials <- new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    let token = tokenHandler.CreateToken(tokenDescriptor)
    tokenHandler.WriteToken(token)

let RegisterUserHandle =
    fun (next : HttpFunc) (ctx : HttpContext) ->    
        task {
            let! request = ctx.BindJsonAsync<RegisterRequest>()
            let user = request.User

            let newUsers = (user :: users)
            users <- newUsers
            let token = generateToken user.Username

            let authorizedUser = { Email = user.Email; Username = user.Username; Bio = ""; Image = ""; Token = token }
            let response : AuthorizedResponse = { User = authorizedUser }
            return! Successful.OK response next ctx
        }


let AuthenticateUserHandle =
    fun (next : HttpFunc) (ctx : HttpContext) ->
        task {
            let! request = ctx.BindJsonAsync<UnauthorizedRequest>();
            let user = request.User

            let usernameAndPasswordMatch (loginAttempt : UnauthorizedUser) (user : UnregisteredUser) =
                loginAttempt.Email = user.Email && loginAttempt.Password = user.Password
            
            let matchingUser = 
                users
                |> List.tryFind (fun x -> usernameAndPasswordMatch user x)

            match matchingUser with 
            | Some u -> 
                let token = generateToken u.Username
                let authorizedUser = { Email = u.Email; Username = u.Username; Bio = ""; Image = ""; Token = token }
                let response : AuthorizedResponse = { User = authorizedUser }
                return! Successful.OK response next ctx
            | None -> return! RequestErrors.UNAUTHORIZED "Basic" "Some Realm" "Unauthorized" next ctx
        }

let getUsers () : HttpHandler =
    fun (next : HttpFunc) (ctx : HttpContext) ->
         Successful.OK users next ctx

let webApp =
    choose [
        GET >=>
            choose [
                route "/" >=> text "Public endpoint."
                route "/greet" >=> authorize >=> greet
                route "/claims" >=> authorize >=> showClaims
                route "/user" >=> authorize >=> getLoggedInUserHandle
            ]
        POST >=>
            choose [
                route "/users" >=> RegisterUserHandle
                route "/users/login" >=> AuthenticateUserHandle
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