using System.Collections.Specialized;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using WareHound.UI.Models;
using WareHound.UI.ViewModels;

namespace WareHound.UI.Views;

public partial class CaptureView : UserControl
{
    private ScrollViewer? _scrollViewer;

    public CaptureView()
    {
        InitializeComponent();
        Loaded += CaptureView_Loaded;
        Unloaded += CaptureView_Unloaded;
        DataContextChanged += CaptureView_DataContextChanged;
    }

    private void CaptureView_DataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is CaptureViewModel oldVm)
        {
            oldVm.PropertyChanged -= ViewModel_PropertyChanged;
        }
        
        if (e.NewValue is CaptureViewModel newVm)
        {
            newVm.PropertyChanged += ViewModel_PropertyChanged;
            UpdateMacColumnsVisibility(newVm.ShowMacAddresses);
        }
    }

    private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(CaptureViewModel.ShowMacAddresses) && sender is CaptureViewModel vm)
        {
            UpdateMacColumnsVisibility(vm.ShowMacAddresses);
        }
    }

    private void UpdateMacColumnsVisibility(bool show)
    {
        var visibility = show ? Visibility.Visible : Visibility.Collapsed;
        SourceMacColumn.Visibility = visibility;
        DestMacColumn.Visibility = visibility;
    }

    private void DataGridRow_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is DataGridRow row && row.Item is PacketInfo packet)
        {
            e.Handled = true;
            try
            {
                var detailWindow = new PacketDetailWindow(packet)
                {
                    Owner = Window.GetWindow(this)
                };
                detailWindow.ShowDialog();
            }
            catch { }
        }
    }

    private void CaptureView_Loaded(object sender, RoutedEventArgs e)
    {
        _scrollViewer = GetScrollViewer(PacketGrid);
        
        if (PacketGrid.ItemsSource is INotifyCollectionChanged collection)
        {
            collection.CollectionChanged += Packets_CollectionChanged;
        }

        if (DataContext is CaptureViewModel vm)
        {
            UpdateMacColumnsVisibility(vm.ShowMacAddresses);
        }
    }

    private void CaptureView_Unloaded(object sender, RoutedEventArgs e)
    {
    }

    private void Packets_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (DataContext is CaptureViewModel viewModel && !viewModel.AutoScroll)
            return;

        if (e.Action == NotifyCollectionChangedAction.Add && _scrollViewer != null)
        {
            Dispatcher.BeginInvoke(() =>
            {
                SmoothScrollToBottom();
            }, System.Windows.Threading.DispatcherPriority.Background);
        }
    }

    private void SmoothScrollToBottom()
    {
        if (_scrollViewer == null) return;

        var targetOffset = _scrollViewer.ScrollableHeight;
        var currentOffset = _scrollViewer.VerticalOffset;
        
        if (Math.Abs(targetOffset - currentOffset) < 1) return;

        var animation = new DoubleAnimation
        {
            From = currentOffset,
            To = targetOffset,
            Duration = TimeSpan.FromMilliseconds(150),
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
        };

        var storyboard = new Storyboard();
        storyboard.Children.Add(animation);
        Storyboard.SetTarget(animation, this);
        Storyboard.SetTargetProperty(animation, new PropertyPath(ScrollOffsetProperty));
        storyboard.Begin();
    }

    public static readonly DependencyProperty ScrollOffsetProperty =
        DependencyProperty.Register("ScrollOffset", typeof(double), typeof(CaptureView),
            new PropertyMetadata(0.0, OnScrollOffsetChanged));

    public double ScrollOffset
    {
        get => (double)GetValue(ScrollOffsetProperty);
        set => SetValue(ScrollOffsetProperty, value);
    }

    private static void OnScrollOffsetChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is CaptureView view && view._scrollViewer != null)
        {
            view._scrollViewer.ScrollToVerticalOffset((double)e.NewValue);
        }
    }

    private static ScrollViewer? GetScrollViewer(DependencyObject obj)
    {
        if (obj is ScrollViewer sv) return sv;
        
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(obj); i++)
        {
            var child = VisualTreeHelper.GetChild(obj, i);
            var result = GetScrollViewer(child);
            if (result != null) return result;
        }
        return null;
    }
}
