namespace Gidsiks.Fail2BanService
{
	public class Worker : BackgroundService
	{
		private readonly ILogger<Worker> _logger;
		private readonly Fail2Ban _fail2Ban;

		public Worker(ILogger<Worker> logger)
		{
			_logger = logger;
			_fail2Ban = new Fail2Ban();
		}

		public override Task StartAsync(CancellationToken cancellationToken)
		{
			_logger.LogTrace("BackgroudService Started at: {time}", DateTimeOffset.UtcNow);
			_fail2Ban.Start();
			return base.StartAsync(cancellationToken);
		}

		protected override async Task ExecuteAsync(CancellationToken stoppingToken)
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				//_logger.LogTrace("BackgroudService Executed at: {time}", DateTimeOffset.Now);
				//_fail2Ban.Check();
				await Task.Delay(TimeSpan.FromMilliseconds(20000), stoppingToken);
				//await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
			}
		}

		public override Task StopAsync(CancellationToken cancellationToken)
		{
			_logger.LogTrace("BackgroudService Stopped at: {time}", DateTimeOffset.UtcNow);
			_fail2Ban.Stop();
			return base.StopAsync(cancellationToken);
		}

	}
}