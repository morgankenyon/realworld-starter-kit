module Models


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
type EmailUser =
    {
        Email : string
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

[<CLIMutable>]
type UserRequest<'T> =
    {
        User : 'T
    }