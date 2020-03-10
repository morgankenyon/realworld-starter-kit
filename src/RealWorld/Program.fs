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
open Models
open System.Threading.Tasks

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
    fun (insertUser : UnregisteredUser -> Task<Result<int, string>>) (registerUser : UnregisteredUser -> AuthorizedUser) (next : HttpFunc) (ctx : HttpContext) ->    
        task {
            let! request = ctx.BindJsonAsync<UserRequest<UnregisteredUser>>()
            let user = request.User

            let! insertUserResult = insertUser user
            
            match insertUserResult with
            | Ok _ ->
                let authorizedUser = registerUser user
                let response : UserResponse<AuthorizedUser> = { User = authorizedUser }
                ctx.Response.ContentType <- "application/json"
                return! Successful.OK response next ctx
            | Error msg ->
                let response : ErrorResponse = { Message = msg }
                ctx.Response.ContentType <- "application/json"
                return! ServerErrors.INTERNAL_ERROR response next ctx
        }

let RegisterUserHandlerBuilder =
    let insertUser = Db.insertUser
    let registerUser = Domain.RegisterUser generateToken

    RegisterUserHandler insertUser registerUser

let AuthenticateUserHandler =
    fun (selectUser : string -> string -> Task<Db.User option>) (authenticateUser : Db.User -> AuthorizedUser) (next : HttpFunc) (ctx : HttpContext) ->
        task {
            let! request = ctx.BindJsonAsync<UserRequest<UnauthorizedUser>>();
            let user = request.User
            
            let! user = selectUser user.Email user.Password

            match user with
            | Some u ->
                let authorizedUser = authenticateUser u
                let response : UserResponse<AuthorizedUser> = { User = authorizedUser }
                ctx.Response.ContentType <- "application/json"
                return! Successful.OK response next ctx
            | None ->
                let response : ErrorResponse = { Message = "Could not find user" }
                ctx.Response.ContentType <- "application/json"
                return! RequestErrors.BAD_REQUEST response next ctx
            
        }

let AuthenticateUserHandlerBuilder =
    let selectUser = Db.selectUser
    let authenticateUser = Domain.AuthenticateUser generateToken

    AuthenticateUserHandler selectUser authenticateUser

let GetLoggedInUserHandler =
    fun (selectUser : string -> Task<Db.User option>) (buildAuthorizedUser : Db.User -> AuthorizedUser) (next : HttpFunc) (ctx : HttpContext) ->
        task {
            let user = ctx.User

            let! loggedInUser = selectUser user.Identity.Name

            match loggedInUser with
            | Some u ->
                let authorizedUser = buildAuthorizedUser u
                let response : UserResponse<AuthorizedUser> = { User = authorizedUser }     
                ctx.Response.ContentType <- "application/json"
                return! Successful.OK response next ctx
            | None ->
                let response : ErrorResponse = { Message = "Could not find user" }
                ctx.Response.ContentType <- "application/json"
                return! RequestErrors.BAD_REQUEST response next ctx
        }

let GetLoggedInUserHandlerBuilder =
    let dbSelect = Db.selectUserByEmail
    let buildAuthorizedUser = Domain.MapDbUser

    GetLoggedInUserHandler dbSelect buildAuthorizedUser

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
                route "/user" >=> authorize >=> GetLoggedInUserHandlerBuilder
            ]
        POST >=>
            choose [
                route "/users" >=> RegisterUserHandlerBuilder
                route "/users/login" >=> AuthenticateUserHandlerBuilder
            ]
        //PUT >=>
        //    choose [
        //        route "/users" >=> InsertUserHandlerBuilder
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