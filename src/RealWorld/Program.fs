﻿open System
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
open Models

// ---------------------------------
// Web app
// ---------------------------------

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



let compareUsername (user : UnregisteredUser ) (username : string) = user.Username = username

let generateToken email =
    let tokenHandler = new JwtSecurityTokenHandler()
    let key = Encoding.ASCII.GetBytes(secret)
    let mutable tokenDescriptor = new SecurityTokenDescriptor()
    let claim = new Claim(ClaimTypes.Name, email)
    let claims = [| claim |]
    tokenDescriptor.Subject <- new ClaimsIdentity(claims)
    tokenDescriptor.Expires <- System.Nullable(DateTime.UtcNow.AddMinutes(2.0))
    tokenDescriptor.SigningCredentials <- new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    let token = tokenHandler.CreateToken(tokenDescriptor)
    tokenHandler.WriteToken(token)

let RegisterUserHandler =
    fun (next : HttpFunc) (ctx : HttpContext) ->    
        task {
            let! request = ctx.BindJsonAsync<UserRequest<UnregisteredUser>>()
            let user = request.User

            let! authorizedUser =
                Db.insertUser user
                |> Domain.RegisterUser user generateToken

            let response : AuthorizedResponse = { User = authorizedUser }
            return! Successful.OK response next ctx
        }

let AuthenticateUserHandler =
    fun (next : HttpFunc) (ctx : HttpContext) ->
        task {
            let! request = ctx.BindJsonAsync<UserRequest<UnauthorizedUser>>();
            let user = request.User
            
            let! authorizedUser =
                Db.selectUser user.Email user.Password
                |> Domain.AuthenticateUser generateToken
            
            let response : AuthorizedResponse = { User = authorizedUser }
            return! Successful.OK response next ctx
        }

let GetLoggedInUserHandler =
    fun (next : HttpFunc) (ctx : HttpContext) ->
        task {
            let user = ctx.User

            let! authorizedUser =
                Db.selectUserByEmail user.Identity.Name
                |> Domain.GetLoggedInUser

            let response : AuthorizedResponse = { User = authorizedUser }
        
            return! Successful.OK response next ctx
        }

//let UpdateUserHandler =
//    fun (next : HttpFunc) (ctx : HttpContext) ->
//        task {
//            let! request = ctx.BindJsonAsync<UserRequest<EmailUser>>();
//            let user = request.User

//            let! 
//        }

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
                route "/user" >=> authorize >=> GetLoggedInUserHandler
            ]
        POST >=>
            choose [
                route "/users" >=> RegisterUserHandler
                route "/users/login" >=> AuthenticateUserHandler
            ]
        //PUT >=>
        //    choose [
        //        route "/users" >=> UpdateUserHandler
        //    ]
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