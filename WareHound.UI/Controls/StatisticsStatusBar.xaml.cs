using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using ScottPlot;

namespace WareHound.UI.Controls
{
    public partial class StatisticsStatusBar : UserControl
    {
        private bool _isExpanded = false;
        private StatisticsStatusBarViewModel? _viewModel;

        public StatisticsStatusBar()
        {
            InitializeComponent();
            
            Loaded += StatisticsStatusBar_Loaded;
            Unloaded += StatisticsStatusBar_Unloaded;
        }

        private void StatisticsStatusBar_Loaded(object sender, RoutedEventArgs e)
        {
            _viewModel = DataContext as StatisticsStatusBarViewModel;
            
            if (_viewModel != null)
            {
                InitializeChart();
                _viewModel.ChartUpdateRequested += OnChartUpdateRequested;
                _viewModel.StartUpdating();
            }
        }

        private void StatisticsStatusBar_Unloaded(object sender, RoutedEventArgs e)
        {
            if (_viewModel != null)
            {
                _viewModel.ChartUpdateRequested -= OnChartUpdateRequested;
                _viewModel.StopUpdating();
            }
        }

        #region Chart Initialization

        private void InitializeChart()
        {
            var plt = PacketsChart.Plot;
            
            // Light theme colors
            var bgColor = ScottPlot.Color.FromHex("#F5F5F7");
            var lineColor = ScottPlot.Color.FromHex("#007AFF");
            var gridColor = ScottPlot.Color.FromHex("#3D3D44");
            
            plt.FigureBackground.Color = bgColor;
            plt.DataBackground.Color = bgColor;
            
            // Hide all axes
            plt.Axes.Left.IsVisible = false;
            plt.Axes.Bottom.IsVisible = false;
            plt.Axes.Right.IsVisible = false;
            plt.Axes.Top.IsVisible = false;
            
            // Configure grid - subtle horizontal lines only
            plt.Grid.MajorLineColor = gridColor.WithAlpha(20);
            plt.Grid.XAxisStyle.IsVisible = false;
            plt.Grid.YAxisStyle.IsVisible = true;
            
            double[] initialData = new double[60];
            
            // Add signal plot for the line
            var signal = plt.Add.Signal(initialData);
            signal.Color = lineColor;
            signal.LineWidth = 2f;

            plt.Axes.SetLimitsX(0, 59);
            plt.Axes.SetLimitsY(0, 10);
            
            PacketsChart.Refresh();
        }

        private void OnChartUpdateRequested(object? sender, double[] data)
        {
            Dispatcher.Invoke(() =>
            {
                try
                {
                    var plt = PacketsChart.Plot;
                    plt.Clear();
                    
                    // Light theme
                    var bgColor = ScottPlot.Color.FromHex("#F5F5F7");
                    var lineColor = ScottPlot.Color.FromHex("#007AFF");
                    var gridColor = ScottPlot.Color.FromHex("#3D3D44");
                    
                    plt.FigureBackground.Color = bgColor;
                    plt.DataBackground.Color = bgColor;
                    
                    plt.Axes.Left.IsVisible = false;
                    plt.Axes.Bottom.IsVisible = false;
                    plt.Axes.Right.IsVisible = false;
                    plt.Axes.Top.IsVisible = false;
                    
                    // Grid - subtle horizontal lines
                    plt.Grid.MajorLineColor = gridColor.WithAlpha(20);
                    plt.Grid.XAxisStyle.IsVisible = false;
                    plt.Grid.YAxisStyle.IsVisible = true;
                    
                    // Find max for scaling
                    double maxVal = data.Length > 0 ? data.Max() : 10;
                    if (maxVal < 10) maxVal = 10;
                    
                    // Add signal plot
                    var signal = plt.Add.Signal(data);
                    signal.Color = lineColor;
                    signal.LineWidth = 2f;
                    
                    // Current value point (last point)
                    if (data.Length > 0)
                    {
                        double lastX = data.Length - 1;
                        double currentValue = data[^1];
                        
                        // Glow effect
                        var glow = plt.Add.Scatter(new double[] { lastX }, new double[] { currentValue });
                        glow.Color = lineColor.WithAlpha(80);
                        glow.MarkerSize = 12;
                        glow.LineWidth = 0;
                        
                        // Main point
                        var point = plt.Add.Scatter(new double[] { lastX }, new double[] { currentValue });
                        point.Color = lineColor;
                        point.MarkerSize = 6;
                        point.LineWidth = 0;
                    }
                    
                    // Set axis limits
                    plt.Axes.SetLimitsX(0, data.Length - 1);
                    plt.Axes.SetLimitsY(0, maxVal * 1.15);
                    
                    PacketsChart.Refresh();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Chart error: {ex.Message}");
                }
            });
        }

        #endregion

        #region UI Events

        private void StatusBar_Click(object sender, MouseButtonEventArgs e)
        {
            _isExpanded = !_isExpanded;
            
            // Animate icon
            var rotation = new DoubleAnimation
            {
                To = _isExpanded ? 180 : 0,
                Duration = TimeSpan.FromMilliseconds(200),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseInOut }
            };
            ExpandIconRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, rotation);
            
            // Show/hide panel
            if (_isExpanded)
            {
                ExpandedPanel.Visibility = Visibility.Visible;
                
                // Fade in animation
                var fadeIn = new DoubleAnimation
                {
                    From = 0,
                    To = 1,
                    Duration = TimeSpan.FromMilliseconds(200)
                };
                ExpandedPanel.BeginAnimation(OpacityProperty, fadeIn);
            }
            else
            {
                // Fade out animation
                var fadeOut = new DoubleAnimation
                {
                    From = 1,
                    To = 0,
                    Duration = TimeSpan.FromMilliseconds(150)
                };
                fadeOut.Completed += (s, args) =>
                {
                    if (!_isExpanded)
                        ExpandedPanel.Visibility = Visibility.Collapsed;
                };
                ExpandedPanel.BeginAnimation(OpacityProperty, fadeOut);
            }
        }

        private void StatusBar_MouseEnter(object sender, MouseEventArgs e)
        {
            StatusBarBorder.Background = new SolidColorBrush((System.Windows.Media.Color)ColorConverter.ConvertFromString("#D2D2D7"));
        }

        private void StatusBar_MouseLeave(object sender, MouseEventArgs e)
        {
            StatusBarBorder.Background = new SolidColorBrush((System.Windows.Media.Color)ColorConverter.ConvertFromString("#E8E8ED"));
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Programmatically expand/collapse the panel
        /// </summary>
        public void ToggleExpanded()
        {
            StatusBar_Click(this, null!);
        }

        /// <summary>
        /// Set the panel state
        /// </summary>
        public void SetExpanded(bool expanded)
        {
            if (_isExpanded != expanded)
            {
                StatusBar_Click(this, null!);
            }
        }

        #endregion
    }
}
