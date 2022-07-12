namespace Gidsiks.Fail2BanService
{
	public class Program
	{
		private static IHost host;

		public static void Main(string[] args)
		{
			host = Host.CreateDefaultBuilder(args)
				.UseWindowsService(configure =>
				{
					configure.ServiceName = @"Gidsiks Fail2Ban Service";
				})
				.ConfigureServices(services =>
				{
					services.AddHostedService<Worker>();
				})
				.Build();

			host.Run();
		}

		public static ILogger<T> GetLogger<T>()
		{
			return host.Services.GetRequiredService<ILogger<T>>();
		}
	}
}