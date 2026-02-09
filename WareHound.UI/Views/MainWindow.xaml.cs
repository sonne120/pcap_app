using Prism.Regions;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using WareHound.UI.Infrastructure.Services;

namespace WareHound.UI.Views;

public partial class MainWindow : Window
{
    private readonly IRegionManager _regionManager;
    private readonly ILoggerService _logger;

    public MainWindow(IRegionManager regionManager, ILoggerService logger)
    {
        InitializeComponent();
        _regionManager = regionManager;
        _logger = logger;

        Loaded += MainWindow_Loaded;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _logger.LogDebug("MainWindow loaded, navigating to CaptureView");

        _regionManager.RequestNavigate("ContentRegion", "CaptureView", result =>
        {
            if (result.Result == true)
            {
                _logger.LogDebug("Successfully navigated to CaptureView");
            }
            else
            {
                _logger.LogError($"Failed to navigate to CaptureView: {result.Error?.Message}");
            }
        });
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            if (WindowState == WindowState.Normal)
                WindowState = WindowState.Maximized;
            else
                WindowState = WindowState.Normal;
        }
        else
        {
            if (WindowState == WindowState.Maximized)
            {
                WindowState = WindowState.Normal;
            }
            DragMove();
        }
    }

    private void btnMinimize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void btnMaximize_Click(object sender, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Normal)
            WindowState = WindowState.Maximized;
        else
            WindowState = WindowState.Normal;
    }

    private void btnClose_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void btnCapture_MouseEnter(object sender, MouseEventArgs e)
    {
        if (Tg_Btn.IsChecked == false)
        {
            NavPopup.PlacementTarget = btnCapture;
            NavPopup.Placement = PlacementMode.Right;
            NavPopup.IsOpen = true;
            PopupHeader.PopupText.Text = "Capture";
        }
    }

    private void btnDashboard_MouseEnter(object sender, MouseEventArgs e)
    {
        if (Tg_Btn.IsChecked == false)
        {
            NavPopup.PlacementTarget = btnDashboard;
            NavPopup.Placement = PlacementMode.Right;
            NavPopup.IsOpen = true;
            PopupHeader.PopupText.Text = "Dashboard";
        }
    }

    private void btnSettings_MouseEnter(object sender, MouseEventArgs e)
    {
        if (Tg_Btn.IsChecked == false)
        {
            NavPopup.PlacementTarget = btnSettings;
            NavPopup.Placement = PlacementMode.Right;
            NavPopup.IsOpen = true;
            PopupHeader.PopupText.Text = "Settings";
        }
    }

    private void btnStatistics_MouseEnter(object sender, MouseEventArgs e)
    {
        if (Tg_Btn.IsChecked == false)
        {
            NavPopup.PlacementTarget = btnStatistics;
            NavPopup.Placement = PlacementMode.Right;
            NavPopup.IsOpen = true;
            PopupHeader.PopupText.Text = "Statistics";
        }
    }

    private void btnLogs_MouseEnter(object sender, MouseEventArgs e)
    {
        if (Tg_Btn.IsChecked == false)
        {
            NavPopup.PlacementTarget = btnLogs;
            NavPopup.Placement = PlacementMode.Right;
            NavPopup.IsOpen = true;
            PopupHeader.PopupText.Text = "Logs";
        }
    }

    private void NavButton_MouseLeave(object sender, MouseEventArgs e)
    {
        NavPopup.IsOpen = false;
    }

    private void FilterTypeComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {

    }
}
