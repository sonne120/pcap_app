using System.Windows;
using Prism.DryIoc;
using Prism.Events;
using Prism.Ioc;
using WareHound.UI.Infrastructure.DependencyInjection;
using WareHound.UI.Infrastructure.Events;
using WareHound.UI.Services;
using WareHound.UI.Views;

namespace WareHound.UI;

public partial class App : PrismApplication
{
    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
        {
            var ex = args.ExceptionObject as Exception;
            var innerMsg = GetFullExceptionMessage(ex);
            MessageBox.Show($"Unhandled exception: {innerMsg}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        };
        
        DispatcherUnhandledException += (sender, args) =>
        {
            var innerMsg = GetFullExceptionMessage(args.Exception);
            MessageBox.Show($"UI exception: {innerMsg}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
        
        base.OnStartup(e);
    }

    protected override void OnInitialized()
    {
        base.OnInitialized();
        
        // Subscribe to theme changes
        var eventAggregator = Container.Resolve<IEventAggregator>();
        eventAggregator.GetEvent<ThemeChangedEvent>().Subscribe(OnThemeChanged);
    }

    private void OnThemeChanged(bool isDarkMode)
    {
        var resources = Application.Current.Resources.MergedDictionaries;
        
        // Remove existing MahApps theme
        var existingTheme = resources.FirstOrDefault(d => 
            d.Source?.OriginalString.Contains("Themes/Dark") == true ||
            d.Source?.OriginalString.Contains("Themes/Light") == true);
        
        if (existingTheme != null)
            resources.Remove(existingTheme);

        // Add the new theme
        var themePath = isDarkMode 
            ? "pack://application:,,,/MahApps.Metro;component/Styles/Themes/Dark.Blue.xaml"
            : "pack://application:,,,/MahApps.Metro;component/Styles/Themes/Light.Blue.xaml";
        
        resources.Add(new ResourceDictionary { Source = new Uri(themePath) });
    }

    private static string GetFullExceptionMessage(Exception? ex)
    {
        if (ex == null) return "Unknown error";
        
        var messages = new System.Text.StringBuilder();
        var current = ex;
        while (current != null)
        {
            messages.AppendLine($"{current.GetType().Name}: {current.Message}");
            current = current.InnerException;
        }
        messages.AppendLine();
        messages.AppendLine(ex.StackTrace);
        return messages.ToString();
    }

    protected override Window CreateShell()
    {
        return Container.Resolve<MainWindow>();
    }

    protected override void RegisterTypes(IContainerRegistry containerRegistry)
    {
        containerRegistry.AddApplicationServices();
        containerRegistry.AddViewModels();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        var sniffer = Container.Resolve<ISnifferService>();
        sniffer.Dispose();
        base.OnExit(e);
    }
}
