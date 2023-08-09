using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWSGenerator
{
    public class UserService 
    {
        public UserService() { }

        public class UserInfo
        {
            public string Id { get; set; }
            public string Password { get; set; }
            public string Name { get; set; }
            public DateTime Birthday { get; set; }
            public string Mobile { get; set; }
            public string Email { get; set; }
            public CompanyInfo Company { get; set; }
        }
        public class CompanyInfo
        {
            public string Name = "trivue";

            public string Address = "서울 양천구";

            public Uri Url = new Uri("https://solyi.kr");
        }
        public UserInfo GetUserInfo()
        {
            UserInfo _info = new UserInfo()
            {
                Id = "solyi",
                Password = "password",
                Name = "솔이",
                Birthday = new DateTime(1991, 5, 15),
                Mobile = "010-6666-7777",
                Email = "solyi@naver.com",
                Company = new CompanyInfo()
            };

            return _info;
        }

        public void GetJWT()
        {
            // 1. HEADER
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            RSAParameters privateKey = rsa.ExportParameters(true);

            var n = Base64UrlEncoder.Encode(privateKey.Modulus);
            var e = Base64UrlEncoder.Encode(privateKey.Exponent);

            var jsonWebKey = new JsonWebKey()
            {
                Kty = JsonWebAlgorithmsKeyTypes.RSA,
                N = n,
                E = e,
            };

            var securityKey = new RsaSecurityKey(privateKey);
            var header = new JwtHeader(new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256))
            {
                { "jwk", jsonWebKey }
            };

            // 2. PAYLOAD
            // 2-1. Data 가져오기
            UserInfo user = this.GetUserInfo();


            // 2-2. 토큰 만료 시간 설정
            DateTimeOffset currentDateTime = DateTimeOffset.Now;
            long nbf = currentDateTime.ToUnixTimeSeconds();

            DateTimeOffset expirationDateTime = currentDateTime.AddHours(24);
            long exp = expirationDateTime.ToUnixTimeSeconds();

            var payload = new JwtPayload()
            { 
                { "iss", user.Company.Url },
                { "sub", user.Name },
                { "nbf", nbf },
                { "exp", exp },
                { "jti", user.Email },
                { "user", user },
            };

            // 3. JWT 생성
            var token = new JwtSecurityToken(header, payload);
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.WriteToken(token);

            Console.WriteLine("\n【JWT】\n" + jwtToken);

            // 4. 디코드
            this.DecodeJWT(jwtToken, n, e);

            // 5. 검증
            var verify = this.VerifyJWT_RS256_Signature(jwtToken, n, e);
            Console.WriteLine("\n【검증】: " + verify);

            //var byteArray = Encoding.UTF8.GetBytes(jwtToken);
            //return byteArray;
        }

        public void DecodeJWT(string token, string n, string e)
        {
            string jwt = token.Replace('_', '/').Replace('-', '+');
            string[] jwsParts = jwt.Split('.');

            for (int i = 0; i < jwsParts.Length; i++)
            {
                int mod4 = jwsParts[i].Length % 4;
                if (mod4 > 0)
                {
                    jwsParts[i] += new string('=', 4 - mod4);
                }
            }
            string headerJson = DecodeBase64ToJson(jwsParts[0]);
            string payloadJson = DecodeBase64ToJson(jwsParts[1]);
            string signatureJson = jwsParts[2];

            Console.WriteLine("\n【header】\n" + headerJson);
            Console.WriteLine("\n【payload】\n" + payloadJson);
            Console.WriteLine("\n【signature】\n" + signatureJson);

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            rsa.ImportParameters(
               new RSAParameters()
               {
                   Exponent = StringFromBase64Url(e),
                   Modulus = StringFromBase64Url(n),
               });

            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                IssuerSigningKey = new RsaSecurityKey(rsa)
            };

            var handler = new JwtSecurityTokenHandler();
            var result = handler.ValidateToken(token, validationParameters, out var validatedToken);
            if (null != result)
            {
                Console.WriteLine("\n【result】");
                foreach (Claim claim in result.Claims)
                {
                    Console.WriteLine("  CLAIM TYPE: " + claim.Type + "; CLAIM VALUE: " + claim.Value);
                }
            }

            Console.WriteLine("\n【ValidatedToken】\n" + validatedToken);
            //JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;
        }

        public bool VerifyJWT_RS256_Signature(string jwt, string publicKey, string exponent)
        {
            var jwtArray = jwt.Split('.');

            string publicKeyFixed = (publicKey.Length % 4 == 0 ? publicKey : publicKey + "====".Substring(publicKey.Length % 4)).Replace("_", "/").Replace("-", "+");
            var publicKeyBytes = Convert.FromBase64String(publicKeyFixed);

            var jwtSignatureFixed = (jwtArray[2].Length % 4 == 0 ? jwtArray[2] : jwtArray[2] + "====".Substring(jwtArray[2].Length % 4)).Replace("_", "/").Replace("-", "+");
            var jwtSignatureBytes = Convert.FromBase64String(jwtSignatureFixed);

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
                new RSAParameters()
                {
                    Modulus = publicKeyBytes,
                    Exponent = Convert.FromBase64String(exponent)
                }
            );

            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(jwtArray[0] + '.' + jwtArray[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            if (rsaDeformatter.VerifySignature(hash, jwtSignatureBytes))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0];
            output = output.Replace('+', '-');
            output = output.Replace('/', '_');
            return output;
        }

        static byte[] StringFromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url 
                : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/").Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        //Base64를 디코딩하여 문자열을 JSON 형식으로 반환하는 함수
        public string DecodeBase64ToJson(string base64String)
        {
            byte[] bytes = Convert.FromBase64String(base64String);
            return Encoding.UTF8.GetString(bytes);
        }
    }
}