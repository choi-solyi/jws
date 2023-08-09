namespace JWSGenerator
{
    internal class Program
    {
        static void Main(string[] args)
        {
            UserService service = new UserService();
            service.GetJWT();
        }
    }
}
