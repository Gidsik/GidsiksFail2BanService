namespace Gidsiks.Fail2BanService
{
	public class Worker : BackgroundService
	{
		private readonly ILogger<Worker> _logger;
		private Fail2Ban _fail2Ban;

		public Worker(ILogger<Worker> logger)
		{
			_logger = logger;
		}

		public override Task StartAsync(CancellationToken cancellationToken)
		{
			_fail2Ban = new Fail2Ban();
			return base.StartAsync(cancellationToken);
		}

		protected override async Task ExecuteAsync(CancellationToken stoppingToken)
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				//_logger.LogTrace("Checking at: {time}", DateTimeOffset.Now);
				//_fail2Ban.Check();
				//await Task.Delay(TimeSpan.FromMilliseconds(2000), stoppingToken);
				await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
			}
		}

		public override Task StopAsync(CancellationToken cancellationToken)
		{
			_fail2Ban.Stop();
			return base.StopAsync(cancellationToken);
		}

	}
}