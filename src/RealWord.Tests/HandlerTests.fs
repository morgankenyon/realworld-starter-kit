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

[<Fact>]
let ``Test Register User Handler Registers`` () =
    let fakeDbCall (_: UnregisteredUser) : Task<Result<int, string>> =
        task {
            let res : Result<int, string> = Ok 1
            return res
        }

    let registerUser (user: UnregisteredUser) : AuthorizedUser =
        { Email = user.Email; Username = user.Username; Bio = "bioCool"; Image = "imageCool"; Token = "tokenCool" }

    let handler = 
        Program.RegisterUserHandler fakeDbCall registerUser

    let unauthorizedUser : UnregisteredUser = { Email = "test@gmail.com"; Password = "test1234"; Username = "test" }
    let userRequest : UserRequest<UnregisteredUser> = { User = unauthorizedUser }
    let postData = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(userRequest))

    let context = buildMockContext(Some postData)

    task {
        let! response = handler next context
        Assert.True(response.IsSome)
        let context = response.Value
        Assert.NotNull(context)
        let body = getBody context
        let userResponse = JsonConvert.DeserializeObject<UserResponse<AuthorizedUser>>(body)
        Assert.NotNull(context)
        Assert.NotNull(userResponse.User)
        let rUser = userResponse.User
        Assert.Equal("test@gmail.com", rUser.Email)
        Assert.Equal("test", rUser.Username)
        Assert.Equal("bioCool", rUser.Bio)
        Assert.Equal("imageCool", rUser.Image)
        Assert.Equal("tokenCool", rUser.Token)
        //Assert.Equal("{\"user\":{\"email\":\"test@gmail.com\",\"username\":\"test\",\"bio\":\"bio\",\"image\":\"image\",\"token\":\"token\"}}", body)
    }