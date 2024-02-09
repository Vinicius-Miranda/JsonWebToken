using DotNteCoreWebApi.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DotNteCoreWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        private static UserEntity _userEntity = new();

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public ActionResult<UserEntity> Register(User userModel)
        {
            if(ModelState.IsValid)
            {
                _userEntity.Name = userModel.Name;
                _userEntity.PasswordHash = BCrypt.Net.BCrypt.HashPassword(userModel.Password);

                return Ok(_userEntity);
            }
            else
            {
                return BadRequest("User invalid!");
            }
        }

        [HttpPost]
        public ActionResult<UserEntity> Login(User userModel)
        {
            if(_userEntity.Name != userModel.Name ||
                !BCrypt.Net.BCrypt.Verify(userModel.Password, _userEntity.PasswordHash))
            {
                return BadRequest("UserName or password not valid.");
            }

            return Ok(CreateTokenJWT());
        }

        private string CreateTokenJWT()
        {
            var claims = new List<Claim>
            {
              new(ClaimTypes.Name, _userEntity.Name)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(2), signingCredentials: creds);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
