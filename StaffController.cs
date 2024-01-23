
using System;
using System.Net;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.DirectoryServices.Protocols;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using HBFTrainingWorkshop.Models;
using HBFTrainingWorkshop.Data;

namespace HBFTrainingWorkshop.Controllers
{
    public class StaffController : Controller
    {
        private readonly ILogger<StaffController> _logger;
        private readonly CGHMNContext _dbContext;

        public StaffController(ILogger<StaffController> logger, CGHMNContext dbContext)
        {
            _logger = logger;
            _dbContext = dbContext;
        }

        public IActionResult Login()
        {
            return View(new LoginViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login([FromForm] string username, string password)
        {
            if (username == null || password == null)
            {
                return View(new LoginViewModel() { Username = username, HasError = true, Error = "Missing required fields" });
            }

            var conn = new LdapConnection(new LdapDirectoryIdentifier("localhost", 10389));

            try
            {
                conn.Credential = new NetworkCredential("cn=admin,ou=users,dc=cghmn,dc=local", "adminpass");
                conn.AuthType = AuthType.Basic;
                conn.SessionOptions.ProtocolVersion = 3;
                conn.Bind();
            }
            catch
            {
                _logger.LogInformation("Admin bind to LDAP failed");

            }

            var filter = "(&(objectclass=person)(cn=" + username + ")(userPassword=" + password + "))";

            // disable complex LDAP injection because the LDAP driver can't handle it
            // https://github.com/dotnet/runtime/issues/38609
            // var filter = "(&(objectclass=person)(cn=" + username + ")(userPassword=" + SSHA(password) + "))";

            _logger.LogInformation(filter);

            try
            {
                var query = new SearchRequest("ou=users,dc=cghmn,dc=local", filter, SearchScope.Subtree);
                var response = (SearchResponse)conn.SendRequest(query);

                if (response.ResultCode == ResultCode.Success && response.Entries.Count > 0)
                {
                    return new OkObjectResult(_dbContext.Flags.FirstOrDefault(f => f.Challenge == "Staff Login").Id);
                }

                return View(new LoginViewModel() { Username = username, HasError = true, Error = "Incorrect username or password" });
            }
            catch (System.DirectoryServices.Protocols.LdapException e)
            {
                _logger.LogInformation($"{e.Message} | {e.ErrorCode}");
                return View(new LoginViewModel() { Username = username, HasError = true, Error = e.Message });
            }
        }

        private string SSHA(string input)
        {

            var sha1 = SHA1.Create();
            var salt = new byte[] { 0xa2, 0x83, 0x18, 0x87 };
            var hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(input).Concat(salt).ToArray());
            var result = "{SSHA}" + System.Convert.ToBase64String(hash.Concat(salt).ToArray());

            return result;
        }
    }
}
