using System;
using System.Diagnostics;
using System.Net;
using System.Threading.Tasks;
using IdentityModel.OidcClient;
using static IdentityModel.OidcConstants;

namespace OpenIddictClientDemo {
    public static class Program {
        public static async Task Main(string[] args) {
            Console.WriteLine("Press any key to start the authentication process.");
            Console.ReadKey();

            // Create a local web server used to receive the authorization response.
            using var listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:7890/");
            listener.Start();

            var options = new OidcClientOptions {
                Authority = "https://localhost:7000/",
                ClientId = "console_app",
                LoadProfile = false,
                RedirectUri = "http://localhost:7890/",
                Scope = StandardScopes.OpenId
            };

            var client = new OidcClient(options);
            var state = await client.PrepareLoginAsync();

            // Launch the system browser to initiate the authentication dance.
            Process.Start(new ProcessStartInfo {
                FileName = state.StartUrl,
                UseShellExecute = true
            });

            // Wait for an authorization response to be posted to the local server.
            while (true) {
                var context = await listener.GetContextAsync();
                context.Response.StatusCode = 204;
                context.Response.Close();

                var result = await client.ProcessResponseAsync(context.Request.Url.Query, state);
                if (result.IsError) {
                    Console.WriteLine("An error occurred: {0}", result.Error);
                }

                else {
                    Console.WriteLine("\n\nClaims:");

                    foreach (var claim in result.User.Claims) {
                        Console.WriteLine("{0}: {1}", claim.Type, claim.Value);
                    }

                    Console.WriteLine();
                    Console.WriteLine("Access token:\n{0}", result.AccessToken);

                    break;
                }
            }

            Console.ReadLine();
        }
    }
}