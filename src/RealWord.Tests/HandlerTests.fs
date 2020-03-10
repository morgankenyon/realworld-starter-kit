module HandlerTests

open System
open Giraffe
open Xunit
open Models
open System.Threading.Tasks
open FSharp.Control.Tasks.V2
open NSubstitute
open Microsoft.AspNetCore.Http
open System.Text
open Newtonsoft.Json
open System.IO
open Giraffe.Serialization
open System.Security.Principal

let next : HttpFunc = Some >> Task.FromResult

//https://github.com/samueleresca/Blog.FSharpOnWeb/blob/master/test/Blog.FSharpWebAPI.Tests/Fixtures.fs
let buildMockContext (body : byte[] option ) =
    let context = Substitute.For<HttpContext>()
    context.RequestServices.GetService(typeof<INegotiationConfig>).Returns(DefaultNegotiationConfig()) |> ignore
    context.RequestServices.GetService(typeof<Giraffe.Serialization.Json.IJsonSerializer>).Returns(NewtonsoftJsonSerializer(NewtonsoftJsonSerializer.DefaultSettings)) |> ignore
    context.Request.Headers.ReturnsForAnyArgs(new HeaderDictionary()) |> ignore
    context.Response.Body <- new MemoryStream()

    if (body.IsSome) then context.Request.Body <- new MemoryStream(body.Value)

    context

let getBody (ctx : HttpContext) =
    ctx.Response.Body.Position <- 0L
    use reader = new StreamReader(ctx.Response.Body, System.Text.Encoding.UTF8)
    reader.ReadToEnd()
    
let registerUser (user: UnregisteredUser) : AuthorizedUser =
    { Email = user.Email; Username = user.Username; Bio = "bioCool"; Image = "imageCool"; Token = "tokenCool" }

let dbToAuthorizedUser (user : Db.User) =
    { Email = user.Email; Username = user.Username; Bio = user.Bio; Image = user.Image; Token = "tokenCool" }

let getPostUser =
    let unauthorizedUser : UnregisteredUser = { Email = "test@gmail.com"; Password = "test1234"; Username = "test" }
    let userRequest : UserRequest<UnregisteredUser> = { User = unauthorizedUser }
    Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(userRequest))
    
let getDbUser () : Db.User =
    { Id = 1; Email = "test@gmail.com"; Username = "user"; Password = "pass"; Bio = "biosphere"; Image = "imagging"; Created = DateTime.UtcNow; Updated = DateTime.UtcNow }

let extractBody<'T> context =
    let body = getBody context
    JsonConvert.DeserializeObject<'T>(body)

[<Fact>]
let ``RegisterUserHandler Registers`` () =
    let fakeDbCall (_: UnregisteredUser) : Task<Result<int, string>> =
        task {
            let res : Result<int, string> = Ok 1
            return res
        }

    let handler = 
        Program.RegisterUserHandler fakeDbCall registerUser

    let context = buildMockContext(Some getPostUser)

    task {
        let! response = handler next context
        Assert.True(response.IsSome)
        let con = response.Value
        Assert.NotNull(con)
        Assert.Equal(200, con.Response.StatusCode)
        Assert.Equal("application/json", con.Response.ContentType)
        let userResponse = extractBody<UserResponse<AuthorizedUser>> con
        Assert.NotNull(userResponse)
        let rUser = userResponse.User
        Assert.Equal("test@gmail.com", rUser.Email)
        Assert.Equal("test", rUser.Username)
        Assert.Equal("bioCool", rUser.Bio)
        Assert.Equal("imageCool", rUser.Image)
        Assert.Equal("tokenCool", rUser.Token)
    }

[<Fact>]
let ``RegisterUserHandler Returns Error On Failure``() =
    let fakeDbCall (_: UnregisteredUser) : Task<Result<int, string>> =
        task {
            let res : Result<int, string> = Error "Could not insert"
            return res
        }

    let handler =
        Program.RegisterUserHandler fakeDbCall registerUser
        
    let context = buildMockContext(Some getPostUser)

    task {
        let! response = handler next context
        Assert.True(response.IsSome)
        let con = response.Value
        Assert.NotNull(con)
        Assert.Equal(500, con.Response.StatusCode)
        Assert.Equal("application/json", con.Response.ContentType)
        let errorResponse = extractBody<ErrorResponse> con
        Assert.Equal("Could not insert", errorResponse.Message)
    }

[<Fact>]
let ``AuthenticateUserHandler Authenticates``() =
    let fakeDbCall(_: string) (_: string) : Task<Db.User option> =
        task {
            return Some { Id = 1; Email = "test@gmail.com"; Username = "user"; Password = "pass"; Bio = "biosphere"; Image = "imagging"; Created = DateTime.UtcNow; Updated = DateTime.UtcNow }
        }

    let handler = 
        Program.AuthenticateUserHandler fakeDbCall dbToAuthorizedUser

    let context = buildMockContext(Some getPostUser)

    task {
        let! response = handler next context
        Assert.True(response.IsSome)
        let con = response.Value
        Assert.NotNull(con)
        Assert.Equal(200, con.Response.StatusCode)
        Assert.Equal("application/json", con.Response.ContentType)
        let userResponse = extractBody<UserResponse<AuthorizedUser>> con
        Assert.NotNull(userResponse)
        let rUser = userResponse.User
        Assert.Equal("test@gmail.com", rUser.Email)
        Assert.Equal("user", rUser.Username)
        Assert.Equal("biosphere", rUser.Bio)
        Assert.Equal("imagging", rUser.Image)
        Assert.Equal("tokenCool", rUser.Token)    
    }

[<Fact>]
let ``AuthenticateUserHandler Fails Correctly``() =
    let fakeDbCall(_: string) (_: string) : Task<Db.User option> =
        task {
            return None
        }

    let handler = 
        Program.AuthenticateUserHandler fakeDbCall dbToAuthorizedUser

    let context = buildMockContext(Some getPostUser)

    task {
        let! response = handler next context
        Assert.True(response.IsSome)
        let con = response.Value
        Assert.NotNull(con)
        Assert.Equal(400, con.Response.StatusCode)
        Assert.Equal("application/json", con.Response.ContentType)
        let errorResponse = extractBody<ErrorResponse> con
        Assert.NotNull(errorResponse)
        Assert.Equal("Could not find user", errorResponse.Message)
    }

[<Fact>]
let ``GetLoggedInUserHandler Succeeds``() =
    let selectUser (_: string) : Task<Db.User option> =
        task {
            return Some (getDbUser())
        }

    let handler = Program.GetLoggedInUserHandler selectUser dbToAuthorizedUser
    
    let context = buildMockContext(None)
    let userToTest = "TestUser"
    let roles = Array.zeroCreate<string>(0)
    let fakeIdentity = GenericIdentity(userToTest)
    let principal = new GenericPrincipal(fakeIdentity, roles)
    context.User <- principal

    task {
        let! response = handler next context
        Assert.True(response.IsSome)
        let con = response.Value
        Assert.NotNull(con)
        Assert.Equal(200, con.Response.StatusCode)
        Assert.Equal("application/json", con.Response.ContentType)
        let userResponse = extractBody<UserResponse<AuthorizedUser>> con
        Assert.NotNull(userResponse)
        let rUser = userResponse.User
        Assert.Equal("test@gmail.com", rUser.Email)
        Assert.Equal("user", rUser.Username)
        Assert.Equal("biosphere", rUser.Bio)
        Assert.Equal("imagging", rUser.Image)
        Assert.Equal("tokenCool", rUser.Token) 
    }

[<Fact>]
let ``GetLoggedInUserHandler Fails for Bad User``() =
    let selectUser (_: string) : Task<Db.User option> =
        task {
            return None
        }

    let handler = Program.GetLoggedInUserHandler selectUser dbToAuthorizedUser
    
    let context = buildMockContext(None)
    let userToTest = "TestUser"
    let roles = Array.zeroCreate<string>(0)
    let fakeIdentity = GenericIdentity(userToTest)
    let principal = new GenericPrincipal(fakeIdentity, roles)
    context.User <- principal
    
    task {
        let! response = handler next context
        Assert.True(response.IsSome)
        let con = response.Value
        Assert.NotNull(con)
        Assert.Equal(400, con.Response.StatusCode)
        Assert.Equal("application/json", con.Response.ContentType)
        let errorResponse = extractBody<ErrorResponse> con
        Assert.NotNull(errorResponse)
        Assert.Equal("Could not find user", errorResponse.Message)
    }
    